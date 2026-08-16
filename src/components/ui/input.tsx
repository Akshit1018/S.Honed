import type { InputHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-12 w-full rounded-md bg-elevated px-4 text-base text-fg shadow-[var(--shadow-border)] outline-none placeholder:text-subtle",
        "transition-[box-shadow] duration-150 ease-out focus-visible:shadow-[var(--shadow-border-hover)]",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({
  className,
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "min-h-28 w-full resize-y rounded-md bg-elevated px-4 py-3 text-base text-fg shadow-[var(--shadow-border)] outline-none placeholder:text-subtle",
        "transition-[box-shadow] duration-150 ease-out focus-visible:shadow-[var(--shadow-border-hover)]",
        className,
      )}
      {...props}
    />
  );
}
