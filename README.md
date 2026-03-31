This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

## Optional Python Engine Bridge

ShieldWall now supports an optional Python detection/mitigation bridge.
If Python is unavailable, the Next.js firewall still works in fallback mode.

### 1) Start the Python bridge (from project root)

```bash
python python_engine_bridge.py
```

This starts a local API on `http://127.0.0.1:5050`.

### 2) Configure Next.js to use the bridge

Create `firewall-dashboard/.env.local`:

```bash
PY_ENGINE_URL=http://127.0.0.1:5050
```

### 3) Start dashboard

```bash
npm run dev
```

When protection is enabled from the Protect tab:
- ShieldWall tries Python mitigation first.
- If unavailable, it automatically falls back to built-in Next.js logic.
- A small mitigation terminal popup opens with live engine logs and demo output.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
