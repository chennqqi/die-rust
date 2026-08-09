import { useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

/// Header field tree node — mirrors Rust `HeaderField` struct.
export interface HeaderField {
  name: string;
  value: string;
  comment?: string;
  children?: HeaderField[];
}

/// Recursive tree node for displaying structured header fields.
/// Each node shows: name | value | comment, with expand/collapse for children.
function TreeNode({ field, depth }: { field: HeaderField; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 1);
  const hasChildren = field.children && field.children.length > 0;

  return (
    <div>
      <div
        className={`flex items-start gap-1 py-0.5 hover:bg-hover rounded px-1 ${
          depth === 0 ? "mt-1 font-medium" : ""
        }`}
        style={{ paddingLeft: `${depth * 16 + 4}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
        role={hasChildren ? "button" : undefined}
      >
        {/* Expand/collapse icon */}
        <span className="w-4 flex-shrink-0">
          {hasChildren ? (
            expanded ? (
              <ChevronDown size={12} className="text-fg-muted" />
            ) : (
              <ChevronRight size={12} className="text-fg-muted" />
            )
          ) : null}
        </span>

        {/* Field name */}
        <span
          className={`text-fg-secondary flex-shrink-0 ${
            depth === 0 ? "text-accent-blue" : ""
          }`}
          style={{ minWidth: depth === 0 ? "auto" : "180px" }}
        >
          {field.name}
        </span>

        {/* Value */}
        {field.value && (
          <span className="mono text-fg-primary text-xs">{field.value}</span>
        )}

        {/* Comment */}
        {field.comment && (
          <span className="text-fg-muted text-xs italic ml-2">
            ; {field.comment}
          </span>
        )}
      </div>

      {/* Children */}
      {hasChildren && expanded && (
        <div>
          {field.children!.map((child, i) => (
            <TreeNode key={i} field={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

/// File header tree view — displays structured PE/ELF/Mach-O header fields.
export function FileHeaderTree({ fields }: { fields: HeaderField[] }) {
  if (fields.length === 0) {
    return (
      <p className="text-fg-muted text-xs">
        No header information available for this file format.
      </p>
    );
  }

  return (
    <div className="text-xs selectable">
      {fields.map((field, i) => (
        <TreeNode key={i} field={field} depth={0} />
      ))}
    </div>
  );
}
