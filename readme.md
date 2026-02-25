# Secure MQTT with CP-ABE

## Run the Project

Start all services (broker, authority, publisher, subscribers):

```bash
docker compose up -d
```

## Inspect Logs (Live)

View logs for each service separately.

### Publisher

```bash
docker compose logs -f publisher
```

### Subscriber 1

```bash
docker compose logs -f subscriber1
```

### Subscriber 2

```bash
docker compose logs -f subscriber2
```

### Authority

```bash
docker compose logs -f authority
```

### Broker

```bash
docker compose logs -f broker
```

## Authority CLI Commands

The authority container stays running and exposes a CLI tool.

You execute commands inside it using:

```bash
docker compose exec authority ./authority <flags>
```

### Generate System Keys

Creates:

- `/keys/public.key`
- `/keys/master.key`

```bash
docker compose exec authority ./authority --setup
```


### Force Regenerate System Keys

⚠ This will delete all previously issued subscriber keys.

```bash
docker compose exec authority ./authority --setup --force
```

---

### Issue Subscriber Private Key

Example: subscriber with attributes `role=operator`, `site=rome`

```bash
docker compose exec authority ./authority --issue --out sub1.key --attrs-json "{\"role\":\"operator\",\"site\":\"rome\"}"
```

Example: subscriber with attributes `role=guest`, `site=milan`

```bash
docker compose exec authority ./authority --issue --out sub2.key --attrs-json "{\"role\":\"guest\",\"site\":\"milan\"}"
```

## Stop Project

Stop containers but keep keys:

```bash
docker compose down
```

Stop containers **and delete keys** (removes volume):

```bash
docker compose down -v
```