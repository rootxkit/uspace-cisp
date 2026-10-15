"use client";

// How the console's tables show what does not fit a column: a long id
// by a short form with the whole id in its tooltip, for a screen reader
// and on a copy button; and the secondary facts of a row behind a row
// expander, so the table fits its card from 1024 px with the sidebar
// open. Nothing is resolved or guessed: every id is the one the API sent.
import { useId, useState, type ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { TableCell, TableRow, cn } from "@rootxkit/uspace-ui/ui";

/** Ids at most this long are shown whole. A display bound. */
export const SHORT_ID_MAX = 12;
/** The leading and trailing characters a longer id is shown by. Display bounds. */
export const SHORT_ID_HEAD = 4;
export const SHORT_ID_TAIL = 6;

/**
 * The id as shown: whole when short, else its first and last characters.
 * A ULID's leading characters are its time, the same for ids made close
 * together, so the tail (its random part) is what tells two apart.
 */
export function shortId(id: string): string {
  return id.length <= SHORT_ID_MAX ? id : `${id.slice(0, SHORT_ID_HEAD)}…${id.slice(-SHORT_ID_TAIL)}`;
}

/** An id, shortened when long, the whole id in its tooltip and for a screen reader. */
export function ShortId({ id, className = "font-mono" }: { id: string; className?: string }) {
  const short = shortId(id);
  if (short === id) {
    return (
      <span className={cn("whitespace-nowrap", className)} data-id={id}>
        {id}
      </span>
    );
  }
  return (
    <span className={cn("whitespace-nowrap", className)} title={id} data-id={id} data-short="true">
      <span aria-hidden="true">{short}</span>
      <span className="sr-only">{id}</span>
    </span>
  );
}

/** A button that copies `value`, named by what it copies. */
export function CopyButton({ value }: { value: string }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const label = t(copied ? "cisp.console.id.copied" : "cisp.console.id.copy", { id: value });
  return (
    <button
      type="button"
      className="inline-flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-surface-sunken hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      aria-label={label}
      title={label}
      data-testid="copy-id"
      onClick={() => {
        void navigator.clipboard
          ?.writeText(value)
          .then(() => setCopied(true))
          .catch(() => setCopied(false));
      }}
    >
      <svg aria-hidden="true" viewBox="0 0 16 16" className="size-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="5" y="5" width="8.5" height="8.5" rx="1.5" />
        <path d="M3 10.5V3.5A1 1 0 0 1 4 2.5h6.5" />
      </svg>
    </button>
  );
}

/** A short id followed by the button that copies the whole one. */
export function CopyId({ id, className }: { id: string; className?: string }) {
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      <ShortId id={id} {...(className === undefined ? {} : { className })} />
      <CopyButton value={id} />
    </span>
  );
}

/** The open state of a row expander and the id of the row it opens. */
export function useExpander(): { open: boolean; toggle(): void; detailsId: string } {
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  return { open, toggle: () => setOpen((o) => !o), detailsId };
}

/** The first cell of an expandable row: the button that shows or hides its details. */
export function ExpandCell({ open, toggle, detailsId, label }: { open: boolean; toggle(): void; detailsId: string; label: string }) {
  const t = useT();
  const name = t(open ? "cisp.console.row.hide_details" : "cisp.console.row.show_details", { row: label });
  return (
    <TableCell className="w-8 pe-0">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={detailsId}
        aria-label={name}
        title={name}
        data-testid="row-expander"
        onClick={toggle}
        className="inline-flex size-7 items-center justify-center rounded text-muted-foreground hover:bg-surface-sunken hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <svg
          aria-hidden="true"
          viewBox="0 0 16 16"
          className={cn("size-3.5 transition-transform", open && "rotate-90")}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
        >
          <path d="M6 3.5 10.5 8 6 12.5" />
        </svg>
      </button>
    </TableCell>
  );
}

/** The details row an ExpandCell opens: one cell across the table. */
export function DetailsRow({ open, detailsId, colSpan, children }: { open: boolean; detailsId: string; colSpan: number; children: ReactNode }) {
  return (
    <TableRow id={detailsId} hidden={!open} data-testid="row-details" className="bg-surface-sunken hover:bg-surface-sunken">
      <TableCell colSpan={colSpan} className="py-3">
        {open && children}
      </TableCell>
    </TableRow>
  );
}

/** A row's secondary facts as a compact term and value list. */
export function Facts({ items }: { items: readonly { term: string; value: ReactNode; id?: string; testId?: string }[] }) {
  return (
    <dl className="m-0 grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-[max-content_minmax(0,1fr)] [&_dt]:text-muted-foreground">
      {items.map((f) => (
        <div key={f.id ?? f.term} className="contents" {...(f.testId === undefined ? {} : { "data-testid": f.testId })}>
          <dt>{f.term}</dt>
          <dd className="m-0 min-w-0 wrap-anywhere">{f.value}</dd>
        </div>
      ))}
    </dl>
  );
}
