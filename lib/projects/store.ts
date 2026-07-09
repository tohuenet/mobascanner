/**
 * JSON-file persistence for Projects — the asset-group entity that links a
 * web scan of an app to a source scan of its repo so findings can be
 * correlated across surfaces.
 *
 * Mirrors `lib/store.ts` deliberately (same ensureRoot / index.json pattern,
 * no database). Layout:
 *   data/
 *     projects/
 *       <projectId>/
 *         project.json     — Project metadata (name, members, targets)
 *         findings.jsonl    — Correlated findings, rewritten idempotently
 *       index.json          — Array of {id, name, createdAt, memberCount} for list view
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { Finding, Project, ProjectMember } from "../types";
import { getScan } from "../store";

const DATA_ROOT = path.join(process.cwd(), "data");
const PROJECTS_ROOT = path.join(DATA_ROOT, "projects");
const INDEX_PATH = path.join(PROJECTS_ROOT, "index.json");

async function ensureRoot() {
  await fs.mkdir(PROJECTS_ROOT, { recursive: true });
  try { await fs.access(INDEX_PATH); }
  catch { await fs.writeFile(INDEX_PATH, "[]", "utf8"); }
}

function projectDir(id: string) { return path.join(PROJECTS_ROOT, id); }

export interface ProjectIndexEntry {
  id: string;
  name: string;
  createdAt: number;
  memberCount: number;
  targets?: Project["targets"];
}

async function readIndex(): Promise<ProjectIndexEntry[]> {
  await ensureRoot();
  try {
    const raw = await fs.readFile(INDEX_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function writeIndex(entries: ProjectIndexEntry[]) {
  await ensureRoot();
  await fs.writeFile(INDEX_PATH, JSON.stringify(entries, null, 2), "utf8");
}

function toIndex(project: Project): ProjectIndexEntry {
  return {
    id: project.id,
    name: project.name,
    createdAt: project.createdAt,
    memberCount: project.members.length,
    targets: project.targets,
  };
}

async function writeProject(project: Project): Promise<void> {
  await fs.mkdir(projectDir(project.id), { recursive: true });
  await fs.writeFile(
    path.join(projectDir(project.id), "project.json"),
    JSON.stringify(project, null, 2),
    "utf8",
  );
  const idx = await readIndex();
  const i = idx.findIndex((e) => e.id === project.id);
  if (i >= 0) idx[i] = toIndex(project);
  else idx.unshift(toIndex(project));
  await writeIndex(idx);
}

export async function createProject(input: {
  name: string;
  targets?: Project["targets"];
  meta?: Record<string, unknown>;
}): Promise<Project> {
  const project: Project = {
    id: randomUUID(),
    name: input.name,
    createdAt: Date.now(),
    targets: input.targets,
    members: [],
    meta: input.meta,
  };
  await fs.mkdir(projectDir(project.id), { recursive: true });
  await fs.writeFile(path.join(projectDir(project.id), "findings.jsonl"), "", "utf8");
  await writeProject(project);
  return project;
}

export async function getProject(id: string): Promise<Project | null> {
  try {
    const raw = await fs.readFile(path.join(projectDir(id), "project.json"), "utf8");
    return JSON.parse(raw) as Project;
  } catch {
    return null;
  }
}

export async function listProjects(): Promise<ProjectIndexEntry[]> {
  return readIndex();
}

/** Patch mutable project fields (name / targets / meta). Returns null if absent. */
export async function updateProject(
  id: string,
  patch: { name?: string; targets?: Project["targets"]; meta?: Record<string, unknown> },
): Promise<Project | null> {
  const project = await getProject(id);
  if (!project) return null;
  if (patch.name !== undefined) project.name = patch.name;
  if (patch.targets !== undefined) project.targets = patch.targets;
  if (patch.meta !== undefined) project.meta = patch.meta;
  await writeProject(project);
  return project;
}

/**
 * Attach a scan to a project. Dedupes by scanId (idempotent) and pulls
 * kind + target from the scan itself. Throws if project/scan is missing so
 * the route can map to 404.
 */
export async function addScanToProject(projectId: string, scanId: string): Promise<Project> {
  const project = await getProject(projectId);
  if (!project) throw new Error(`project not found: ${projectId}`);
  const scan = await getScan(scanId);
  if (!scan) throw new Error(`scan not found: ${scanId}`);
  if (!project.members.some((m) => m.scanId === scanId)) {
    const member: ProjectMember = {
      scanId,
      kind: scan.kind,
      target: scan.target.value,
      addedAt: Date.now(),
    };
    project.members.push(member);
    await writeProject(project);
  }
  return project;
}

export async function removeScanFromProject(projectId: string, scanId: string): Promise<Project> {
  const project = await getProject(projectId);
  if (!project) throw new Error(`project not found: ${projectId}`);
  const before = project.members.length;
  project.members = project.members.filter((m) => m.scanId !== scanId);
  if (project.members.length !== before) await writeProject(project);
  return project;
}

export async function deleteProject(id: string): Promise<void> {
  await fs.rm(projectDir(id), { recursive: true, force: true });
  const idx = await readIndex();
  await writeIndex(idx.filter((e) => e.id !== id));
}

/**
 * Rewrite the project's correlated findings idempotently (atomic tmp+rename,
 * never append) — re-running correlation replaces, never duplicates.
 */
export async function writeProjectFindings(projectId: string, findings: Finding[]): Promise<void> {
  await ensureRoot();
  const dir = projectDir(projectId);
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, "findings.jsonl");
  const tmp = file + ".tmp";
  const body = findings.map((f) => JSON.stringify(f)).join("\n") + (findings.length ? "\n" : "");
  await fs.writeFile(tmp, body, "utf8");
  await fs.rename(tmp, file);
}

export async function listProjectFindings(projectId: string): Promise<Finding[]> {
  try {
    const raw = await fs.readFile(path.join(projectDir(projectId), "findings.jsonl"), "utf8");
    if (!raw.trim()) return [];
    return raw.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Finding);
  } catch {
    return [];
  }
}

/**
 * Reverse lookup: which projects contain `scanId` as a member, each with its
 * correlated-finding count. Powers the scan→project banner on the scan report.
 * Walks the lightweight index, then reads each candidate's project.json (for
 * membership) and findings.jsonl (for the count). Returns [] when the scan is in
 * no project.
 */
export async function findProjectsForScan(
  scanId: string,
): Promise<{ id: string; name: string; correlatedCount: number }[]> {
  const index = await listProjects();
  const out: { id: string; name: string; correlatedCount: number }[] = [];
  for (const entry of index) {
    const project = await getProject(entry.id);
    if (!project?.members.some((m) => m.scanId === scanId)) continue;
    const findings = await listProjectFindings(entry.id);
    out.push({ id: project.id, name: project.name, correlatedCount: findings.length });
  }
  return out;
}

export const PROJECT_DATA_PATHS = { DATA_ROOT, PROJECTS_ROOT, INDEX_PATH };
