import { Link } from 'react-router';
import { EmptyState, PageHeader } from '../components/ui';
import { useTitle } from '../lib/useTitle';

export function NotFoundPage() {
  useTitle('Not found');
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="There is nothing at this address.">
        <Link to="/" className="text-accent underline underline-offset-2">
          Go to the overview
        </Link>
      </EmptyState>
    </>
  );
}
