import { notFound } from "next/navigation";
import { listScans } from "@/lib/store";
import { getProject, listProjectFindings } from "@/lib/projects/store";
import { ProjectDetail } from "@/components/projects/ProjectDetail";

export const dynamic = "force-dynamic";

export default async function ProjectDetailPage(props: PageProps<"/projects/[id]">) {
  const { id } = await props.params;
  const project = await getProject(id);
  if (!project) notFound();
  const [scans, findings] = await Promise.all([listScans(), listProjectFindings(id)]);
  return <ProjectDetail initialProject={project} scans={scans} initialFindings={findings} />;
}
