import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "react-i18next";
import { Bookmark, MessageSquare, Tag, Trash2 } from "lucide-react";

export interface AnnotationEntry {
  offset: number;
  text: string;
  color: string;
  created: number;
}

export interface AnnotationsDto {
  file_sha256: string;
  stale: boolean;
  bookmarks: AnnotationEntry[];
  comments: AnnotationEntry[];
  labels: AnnotationEntry[];
}

export type AnnotationKind = "bookmark" | "comment" | "label";

/** Load the annotation store for a file (sidecar `<file>.diec.json`). */
export async function loadAnnotations(path: string): Promise<AnnotationsDto> {
  return invoke<AnnotationsDto>("list_annotations", { path });
}

/** Insert or replace the entry at (kind, offset). Returns the fresh store. */
export async function upsertAnnotation(
  path: string,
  kind: AnnotationKind,
  offset: number,
  text: string,
  color = "",
): Promise<AnnotationsDto> {
  return invoke<AnnotationsDto>("upsert_annotation", { path, kind, offset, text, color });
}

/** Delete the entry at (kind, offset). Returns the fresh store. */
export async function deleteAnnotation(
  path: string,
  kind: AnnotationKind,
  offset: number,
): Promise<AnnotationsDto> {
  return invoke<AnnotationsDto>("delete_annotation", { path, kind, offset });
}

const KIND_ICON: Record<AnnotationKind, typeof Bookmark> = {
  bookmark: Bookmark,
  comment: MessageSquare,
  label: Tag,
};

/**
 * Annotation list — bookmarks/comments/labels persisted in the file's
 * sidecar store (upstream XInfoDB parity). `onJump` scrolls the host
 * view to the entry's offset when provided.
 */
export function AnnotationsPanel({
  path,
  annotations,
  onChanged,
  onJump,
}: {
  path: string;
  annotations: AnnotationsDto | null;
  onChanged: (dto: AnnotationsDto) => void;
  onJump?: (offset: number) => void;
}) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);

  const groups: { kind: AnnotationKind; entries: AnnotationEntry[] }[] = [
    { kind: "bookmark", entries: annotations?.bookmarks ?? [] },
    { kind: "comment", entries: annotations?.comments ?? [] },
    { kind: "label", entries: annotations?.labels ?? [] },
  ];
  const total = groups.reduce((n, g) => n + g.entries.length, 0);

  const remove = useCallback(
    async (kind: AnnotationKind, offset: number) => {
      try {
        setError(null);
        onChanged(await deleteAnnotation(path, kind, offset));
      } catch (e) {
        setError(String(e));
      }
    },
    [path, onChanged],
  );

  if (total === 0 && !annotations?.stale) return null;

  return (
    <div className="mt-2 border border-border rounded p-2 text-xs">
      {annotations?.stale && (
        <div className="text-accent-yellow mb-1">{t("ann.stale")}</div>
      )}
      {error && <div className="text-red-600 mb-1">{error}</div>}
      {groups.map(
        (g) =>
          g.entries.length > 0 && (
            <div key={g.kind} className="mb-1">
              {g.entries.map((e) => {
                const Icon = KIND_ICON[g.kind];
                return (
                  <div key={`${g.kind}-${e.offset}`} className="flex items-center gap-2 py-0.5">
                    <Icon size={11} className="text-fg-muted shrink-0" />
                    <button
                      className="mono text-accent-blue hover:underline"
                      onClick={() => onJump?.(e.offset)}
                      title={t("ann.jump")}
                    >
                      0x{e.offset.toString(16).toUpperCase()}
                    </button>
                    <span className="text-fg-primary truncate" title={e.text}>
                      {e.text}
                    </span>
                    <span className="flex-1" />
                    <button
                      className="text-fg-muted hover:text-red-500"
                      onClick={() => remove(g.kind, e.offset)}
                      title={t("ann.delete")}
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                );
              })}
            </div>
          ),
      )}
    </div>
  );
}
