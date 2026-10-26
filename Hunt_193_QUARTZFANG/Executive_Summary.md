# Executive Summary: Operation QUARTZFANG (cyber range)

I investigated an attack on a web portal during a cyber range hunt, and finished all 28 questions. The portal had a preview feature that fetches web addresses. The attacker used it to reach a service on the server itself, which started a hidden remote shell as root. From there it read a config file, took the logins inside, dumped database tables, browsed the container registry, packed and encrypted its loot, and uploaded it to an outside address. It finished by creating a new admin account so it could come back.

An AI agent did most of the work, with a person approving at four points. I know because the commands came 1 to 6 seconds apart, with quiet gaps of 11 to 17 minutes between bursts. The agent's own log also made two claims that the logs prove false: it said it stole secrets from the admin platform (the server said no, 403) and that it found database credentials in an image (it only read a vulnerability report).

Three normal things looked like the attack and were not: the app's own use of the same login, a nightly backup, and a spike in database connections. I told each apart with a different check.

One limit: some logs are missing. I can't see the Redis step, what the env command printed, or how much data was uploaded.

What I would fix: only let the preview feature fetch web addresses, lock down Redis, take root cron jobs off the web server, and rotate the stolen logins.
