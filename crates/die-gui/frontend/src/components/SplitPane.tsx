import { useState, useRef, useCallback, useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

/**
 * A vertical split pane with a draggable divider.
 *
 * Mirrors upstream DIE's QSplitter(Vertical) behavior: the top pane
 * holds the TreeView results, the bottom pane holds the signature
 * source editor. The divider can be dragged to resize.
 */
export function SplitPane({
  top,
  bottom,
  initialBottomHeight = 240,
  minTopHeight = 80,
  minBottomHeight = 80,
  showBottom,
}: {
  top: ReactNode;
  bottom: ReactNode;
  initialBottomHeight?: number;
  minTopHeight?: number;
  minBottomHeight?: number;
  showBottom: boolean;
}) {
  const { t } = useTranslation();
  const [bottomHeight, setBottomHeight] = useState(initialBottomHeight);
  const [dragging, setDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const startYRef = useRef(0);
  const startBottomRef = useRef(0);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setDragging(true);
    startYRef.current = e.clientY;
    startBottomRef.current = bottomHeight;
  }, [bottomHeight]);

  useEffect(() => {
    if (!dragging) return;

    const onMouseMove = (e: MouseEvent) => {
      if (!containerRef.current) return;
      const containerHeight = containerRef.current.clientHeight;
      const delta = startYRef.current - e.clientY;
      const newBottom = Math.max(
        minBottomHeight,
        Math.min(containerHeight - minTopHeight, startBottomRef.current + delta)
      );
      setBottomHeight(newBottom);
    };

    const onMouseUp = () => setDragging(false);

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    // Disable text selection while dragging.
    document.body.style.userSelect = "none";
    document.body.style.cursor = "row-resize";

    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [dragging, minBottomHeight, minTopHeight]);

  return (
    <div ref={containerRef} className="flex flex-col h-full overflow-hidden">
      {/* Top pane */}
      <div className="flex-1 overflow-auto min-h-0">{top}</div>

      {/* Draggable divider + bottom pane */}
      {showBottom && (
        <>
          <div
            onMouseDown={onMouseDown}
            className="splitter-h"
            title={t("split.drag")}
          >
            <div className="splitter-h-grip" />
          </div>
          <div style={{ height: bottomHeight }} className="overflow-hidden flex-shrink-0">
            {bottom}
          </div>
        </>
      )}
    </div>
  );
}
