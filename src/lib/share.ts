import { createServerFn } from "@tanstack/react-start";
import { getSql } from "@/lib/db";
import { type Report, parseReport } from "@/lib/report";

function token() {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 16);
}

export const createShare = createServerFn({ method: "POST" })
  .validator((input: { report: Report }) => {
    if (!input?.report?.target) throw new Error("Nothing to share.");
    return { report: input.report };
  })
  .handler(async ({ data }) => {
    const sql = await getSql();
    const id = token();
    const json = JSON.stringify(data.report);
    if (json.length > 400_000) throw new Error("Brief is too large to share.");
    await sql`
      insert into shares (token, target, report_json)
      values (${id}, ${data.report.target.slice(0, 400)}, ${json})
    `;
    return { token: id };
  });

export const getShare = createServerFn({ method: "GET" })
  .validator((input: { token: string }) => {
    const t = String(input.token ?? "").trim();
    if (!/^[a-z0-9]{8,32}$/i.test(t)) throw new Error("That share link is not valid.");
    return { token: t };
  })
  .handler(async ({ data }) => {
    const sql = await getSql();
    const rows = await sql<{ report_json: string; target: string }>`
      select report_json, target from shares where token = ${data.token} limit 1
    `;
    const row = rows[0];
    if (!row) throw new Error("This share link has expired or never existed.");
    const report = parseReport(row.report_json);
    if (!report) throw new Error("This brief could not be opened.");
    return { report, target: row.target };
  });
