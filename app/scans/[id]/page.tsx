import { notFound } from "next/navigation";
import { getScan, listFindings } from "@/lib/store";
import { ScanDetailClient } from "./ScanDetailClient";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage(props: PageProps<"/scans/[id]">) {
  const { id } = await props.params;
  const scan = await getScan(id);
  if (!scan) notFound();
  const findings = await listFindings(id);
  return <ScanDetailClient initialScan={scan} initialFindings={findings} />;
}
