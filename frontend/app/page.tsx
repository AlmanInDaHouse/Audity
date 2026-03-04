import Link from 'next/link';

export default function HomePage() {
  return (
    <main>
      <div className="card">
        <h1>Audity MVP</h1>
        <p>Compliance auditing in one click.</p>
        <Link href="/login">Go to login</Link>
      </div>
    </main>
  );
}
