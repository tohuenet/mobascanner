import { notFound } from "next/navigation";
import { getScan, listFindings } from "@/lib/store";
import { findProjectsForScan } from "@/lib/projects/store";
import { ScanDetailClient } from "./ScanDetailClient";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage(props: PageProps<"/scans/[id]">) {
  const { id } = await props.params;
  const scan = await getScan(id);
  if (!scan) notFound();
  // Load findings + any parent projects in parallel; `projects` is [] when the
  // scan is a member of none (the banner then renders nothing).
  const [findings, projects] = await Promise.all([
    listFindings(id),
    findProjectsForScan(id),
  ]);
  return (
    <ScanDetailClient initialScan={scan} initialFindings={findings} projects={projects} />
  );
}
