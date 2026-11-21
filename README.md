# connect (Netlify version)

Deploy steps (GitHub method):
1. Create a free account at github.com and make a new empty repository called `connect`.
2. Upload ALL files from this folder to it (click "uploading an existing file", drag everything in, including the `public` and `netlify` folders, `netlify.toml` and `package.json`).
3. At app.netlify.com choose Add new site > Import an existing project > GitHub > pick `connect`.
4. Leave the build settings as they are and click Deploy. When it finishes you get a public address like https://something.netlify.app
5. Open it, create your account, and send the address to the other person so they can create theirs.

Accounts and messages are stored in Netlify Blobs, so they survive restarts.
