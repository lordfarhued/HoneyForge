import argparse
import getpass
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.audit import write_audit
from app.database import SessionLocal
from app.jobs import ALLOWED_TRAP_COMMANDS, create_trap_job
from app.models import EnrollmentToken, Host, HoneypotInstance, HostStatus, InteractionLevel, TrapProfile, TrapStatus, User, UserRole, utcnow
from app.security import hash_password, token_hash


def create_user(args: argparse.Namespace) -> int:
    try:
        email = validate_email(args.email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        print(f"Ошибка email: {exc}", file=sys.stderr)
        return 2

    password = getpass.getpass("Пароль (не менее 12 символов): ")
    confirmation = getpass.getpass("Повторите пароль: ")
    if password != confirmation:
        print("Пароли не совпадают.", file=sys.stderr)
        return 2
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    with SessionLocal() as db:
        existing = db.scalar(select(User).where((User.username == args.username) | (User.email == email)))
        if existing:
            print("Пользователь с таким именем или email уже существует.", file=sys.stderr)
            return 3
        user = User(username=args.username, email=email, role=UserRole(args.role), password_hash=password_hash)
        db.add(user)
        db.commit()
        print(f"Пользователь {user.username} создан с ролью {user.role.value}.")
    return 0


def create_local_enrollment(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists():
        print("Enrollment token output already exists; refusing to overwrite it.", file=sys.stderr)
        return 2
    if args.ttl_minutes < 1 or args.ttl_minutes > 60:
        print("TTL must be between 1 and 60 minutes.", file=sys.stderr)
        return 2

    raw_token = secrets.token_urlsafe(48)
    expires_at = utcnow() + timedelta(minutes=args.ttl_minutes)
    with SessionLocal() as db:
        profile = db.scalar(select(TrapProfile).where(TrapProfile.name == args.profile))
        if not profile:
            print("Requested profile does not exist.", file=sys.stderr)
            return 3
        host = Host(
            name=args.host,
            management_address=args.address,
            description="Local Docker agent used only for stage-2 verification",
            status=HostStatus.OFFLINE,
        )
        instance = HoneypotInstance(
            name=args.instance,
            host=host,
            profile=profile,
            status=TrapStatus.PENDING,
        )
        enrollment = EnrollmentToken(
            host=host,
            token_hash=token_hash(raw_token),
            expires_at=expires_at,
        )
        db.add_all([host, instance, enrollment])
        try:
            db.flush()
            write_audit(
                db,
                actor=None,
                action="agent.local_test_enrollment_created",
                entity_type="host",
                entity_id=host.id,
                after={"host": host.name, "instance": instance.name, "profile": profile.name},
                source_ip="local-cli",
            )
            db.commit()
        except IntegrityError:
            db.rollback()
            print("Host or instance name already exists.", file=sys.stderr)
            return 4

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as token_file:
            token_file.write(raw_token)
        output.chmod(0o600)
    except OSError:
        print("Enrollment was created, but its token file could not be written.", file=sys.stderr)
        return 5
    print("Local test enrollment created; the token was written to the requested protected file.")
    return 0


def ensure_stage3_local(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        host = db.scalar(select(Host).where(Host.name == args.host))
        if not host:
            print("Local stage-2 host does not exist.", file=sys.stderr)
            return 3
        profile = db.scalar(select(TrapProfile).where(TrapProfile.name == "medium-web-ssh"))
        if not profile:
            profile = TrapProfile(
                name="medium-web-ssh",
                description="Local Medium fake HTTP and fake SSH profile for stage 3",
                interaction_level=InteractionLevel.MEDIUM,
                services=[
                    {"name": "http", "protocol": "tcp", "port": 8082, "banner": "nginx"},
                    {
                        "name": "ssh",
                        "protocol": "tcp",
                        "port": 2222,
                        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                    },
                ],
                bait_credentials=[{"username": "backup", "password": "backup"}],
                logging={
                    "capture_connections": True,
                    "capture_credentials": True,
                    "capture_commands": True,
                    "capture_payloads": False,
                },
                masking={
                    "endpoint_path": "/assets/telemetry",
                    "process_name": "system-metrics",
                    "install_path": "/opt/system-metrics",
                },
            )
            db.add(profile)
            db.flush()
            write_audit(
                db,
                actor=None,
                action="profile.stage3_local_created",
                entity_type="trap_profile",
                entity_id=profile.id,
                after={"name": profile.name, "interaction_level": profile.interaction_level.value},
                source_ip="local-cli",
            )
        instance = db.scalar(select(HoneypotInstance).where(HoneypotInstance.name == args.instance))
        if not instance:
            instance = HoneypotInstance(
                name=args.instance,
                host=host,
                profile=profile,
                status=TrapStatus.PENDING,
            )
            db.add(instance)
            db.flush()
            write_audit(
                db,
                actor=None,
                action="trap.stage3_local_created",
                entity_type="honeypot_instance",
                entity_id=instance.id,
                after={"name": instance.name, "profile": profile.name, "host": host.name},
                source_ip="local-cli",
            )
        stage3_instances = list(
            db.scalars(
                select(HoneypotInstance)
                .join(HoneypotInstance.profile)
                .where(
                    HoneypotInstance.host_id == host.id,
                    TrapProfile.interaction_level.in_([InteractionLevel.LOW, InteractionLevel.MEDIUM]),
                )
            )
        )
        for trap in stage3_instances:
            create_trap_job(
                db,
                instance=trap,
                command="start_trap",
                actor=None,
                source_ip="local-cli",
                idempotency_key=f"stage3-bootstrap:start:{trap.id}:v{trap.profile.config_version}",
            )
        db.commit()
    print("Stage-3 local profiles, instances, and allowlisted start jobs are ready.")
    return 0


def queue_trap_job(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        instance = db.scalar(select(HoneypotInstance).where(HoneypotInstance.name == args.instance))
        if not instance:
            print("Trap instance does not exist.", file=sys.stderr)
            return 3
        create_trap_job(
            db,
            instance=instance,
            command=args.trap_command,
            actor=None,
            source_ip="local-cli",
        )
        db.commit()
    print("Allowlisted trap job queued.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Администрирование HoneyForge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-user", help="Создать пользователя без стандартного пароля")
    create.add_argument("--username", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--role", choices=[role.value for role in UserRole], default=UserRole.OBSERVER.value)
    create.set_defaults(handler=create_user)
    enrollment = subparsers.add_parser(
        "create-local-enrollment",
        help="Create a local test host and write its one-time token to a file without printing it",
    )
    enrollment.add_argument("--profile", required=True)
    enrollment.add_argument("--host", required=True)
    enrollment.add_argument("--instance", required=True)
    enrollment.add_argument("--address", default="local-agent")
    enrollment.add_argument("--ttl-minutes", type=int, default=15)
    enrollment.add_argument("--output", required=True)
    enrollment.set_defaults(handler=create_local_enrollment)
    stage3 = subparsers.add_parser(
        "ensure-stage3-local",
        help="Create the idempotent local Medium profile and queue Low/Medium start jobs",
    )
    stage3.add_argument("--host", default="stage2-local-test")
    stage3.add_argument("--instance", default="stage3-medium-trap")
    stage3.set_defaults(handler=ensure_stage3_local)
    trap_job = subparsers.add_parser("queue-trap-job", help="Queue one strictly allowlisted trap job")
    trap_job.add_argument("--instance", required=True)
    trap_job.add_argument("--command", dest="trap_command", choices=sorted(ALLOWED_TRAP_COMMANDS), required=True)
    trap_job.set_defaults(handler=queue_trap_job)
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
