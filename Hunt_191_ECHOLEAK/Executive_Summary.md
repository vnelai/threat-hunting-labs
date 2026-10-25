# Executive Summary: Operation ECHOLEAK (cyber range)

I investigated how a Copilot assistant leaked company information during a cyber range hunt. An employee got an email from outside with a report attached. She opened it and asked Copilot to summarise it. The document had hidden instructions in it, and Copilot followed them. It searched Finance, Executive, HR and IT files, read 13 of them, and put 13 image links in its replies that pointed to an outside website. Loading those images sent the file names out. It was only the names, not the file contents.

I know this was an attack and not normal use for four reasons. Copilot read files every 2 seconds, kept going after she stopped typing, opened files she had never touched, and wrote links to an outside domain. The other 34 Copilot sessions in the same two hours did none of that. Her account was fine: two normal sign-ins from one London address, with MFA.

One limit: I can show Copilot wrote the links, but without network logs I can't show the outside server received them.

What I would fix: only let Copilot show images from approved sites, treat outside documents as untrusted, and cut access to files people don't need.
