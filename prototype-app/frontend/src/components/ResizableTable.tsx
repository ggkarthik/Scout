import React from 'react';

type Props = {
  storageKey: string;
  children: React.ReactNode;
  minColumnWidth?: number;
};

type ColumnOption = {
  originalIndex: number;
  label: string;
  hidden: boolean;
};

const ORDER_KEY_SUFFIX = ':order';
const HIDDEN_KEY_SUFFIX = ':hidden';
const DEFAULT_HIDDEN_APPLIED_KEY_SUFFIX = ':default-hidden-applied';

function readStoredWidths(storageKey: string): Record<string, number> | null {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const widths: Record<string, number> = {};
      parsed.forEach((value, index) => {
        const numeric = Number(value);
        if (Number.isFinite(numeric) && numeric > 0) {
          widths[String(index)] = numeric;
        }
      });
      return Object.keys(widths).length > 0 ? widths : null;
    }
    if (!parsed || typeof parsed !== 'object') return null;
    const widths: Record<string, number> = {};
    Object.entries(parsed).forEach(([key, value]) => {
      const numeric = Number(value);
      if (Number.isFinite(numeric) && numeric > 0) {
        widths[key] = numeric;
      }
    });
    return Object.keys(widths).length > 0 ? widths : null;
  } catch {
    return null;
  }
}

function writeStoredWidths(storageKey: string, headers: HTMLTableCellElement[]): void {
  try {
    const existing = readStoredWidths(storageKey) ?? {};
    headers.forEach((header, index) => {
      if (header.style.display === 'none') {
        return;
      }
      const width = Math.round(header.getBoundingClientRect().width);
      if (!Number.isFinite(width) || width <= 0) {
        return;
      }
      const originalIndex = header.dataset.originalIndex ?? String(index);
      existing[originalIndex] = width;
    });
    window.localStorage.setItem(storageKey, JSON.stringify(existing));
  } catch {
    // no-op for storage failures
  }
}

function readStoredOrder(storageKey: string): number[] | null {
  try {
    const raw = window.localStorage.getItem(`${storageKey}${ORDER_KEY_SUFFIX}`);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const order = parsed
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value >= 0);
    return order.length === 0 ? null : order;
  } catch {
    return null;
  }
}

function writeStoredOrder(storageKey: string, headers: HTMLTableCellElement[]): void {
  try {
    const order = headers.map((header, index) => {
      const parsed = Number(header.dataset.originalIndex ?? index);
      return Number.isInteger(parsed) && parsed >= 0 ? parsed : index;
    });
    window.localStorage.setItem(`${storageKey}${ORDER_KEY_SUFFIX}`, JSON.stringify(order));
  } catch {
    // no-op for storage failures
  }
}

function readStoredHidden(storageKey: string, columnCount: number): Set<number> {
  try {
    const raw = window.localStorage.getItem(`${storageKey}${HIDDEN_KEY_SUFFIX}`);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    const values = parsed
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value >= 0 && value < columnCount);
    return new Set(values);
  } catch {
    return new Set();
  }
}

function hasStoredHiddenPreference(storageKey: string): boolean {
  try {
    return window.localStorage.getItem(`${storageKey}${HIDDEN_KEY_SUFFIX}`) != null;
  } catch {
    return false;
  }
}

function readStoredDefaultHiddenApplied(storageKey: string, columnCount: number): Set<number> {
  try {
    const raw = window.localStorage.getItem(`${storageKey}${DEFAULT_HIDDEN_APPLIED_KEY_SUFFIX}`);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    const values = parsed
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value >= 0 && value < columnCount);
    return new Set(values);
  } catch {
    return new Set();
  }
}

function writeStoredDefaultHiddenApplied(storageKey: string, values: Set<number>): void {
  try {
    const ordered = Array.from(values).sort((a, b) => a - b);
    window.localStorage.setItem(`${storageKey}${DEFAULT_HIDDEN_APPLIED_KEY_SUFFIX}`, JSON.stringify(ordered));
  } catch {
    // no-op for storage failures
  }
}

function defaultHiddenColumns(headers: HTMLTableCellElement[]): Set<number> {
  const values = new Set<number>();
  headers.forEach((header, index) => {
    const marker = (header.dataset.defaultHidden ?? '').trim().toLowerCase();
    if (marker === 'true' || marker === '1' || marker === 'yes') {
      values.add(originalIndexForHeader(header, index));
    }
  });
  return values;
}

function writeStoredHidden(storageKey: string, hiddenColumns: Set<number>): void {
  try {
    const values = Array.from(hiddenColumns).sort((a, b) => a - b);
    window.localStorage.setItem(`${storageKey}${HIDDEN_KEY_SUFFIX}`, JSON.stringify(values));
  } catch {
    // no-op for storage failures
  }
}

function isValidOrder(order: number[] | null, columnCount: number): order is number[] {
  if (!order || order.length !== columnCount) {
    return false;
  }
  const unique = new Set(order);
  if (unique.size !== columnCount) {
    return false;
  }
  for (let i = 0; i < columnCount; i += 1) {
    if (!unique.has(i)) {
      return false;
    }
  }
  return true;
}

function applyColumnOrder(table: HTMLTableElement, order: number[]): void {
  const rows = Array.from(table.querySelectorAll('tr')) as HTMLTableRowElement[];
  rows.forEach((row) => {
    const cells = Array.from(row.cells);
    if (cells.length !== order.length) {
      return;
    }
    const reordered = order.map((index) => cells[index]).filter(Boolean);
    reordered.forEach((cell) => row.appendChild(cell));
  });
}

function moveColumn(table: HTMLTableElement, fromIndex: number, toIndex: number): void {
  if (fromIndex === toIndex) return;
  const rows = Array.from(table.querySelectorAll('tr')) as HTMLTableRowElement[];
  rows.forEach((row) => {
    const cells = Array.from(row.cells);
    if (fromIndex < 0 || toIndex < 0 || fromIndex >= cells.length || toIndex >= cells.length) {
      return;
    }
    const movingCell = cells[fromIndex];
    const referenceCell = cells[toIndex];
    if (!movingCell || !referenceCell) {
      return;
    }
    if (fromIndex < toIndex) {
      row.insertBefore(movingCell, referenceCell.nextSibling);
    } else {
      row.insertBefore(movingCell, referenceCell);
    }
  });
}

function extractHeaderLabel(header: HTMLTableCellElement): string {
  const clone = header.cloneNode(true) as HTMLElement;
  clone.querySelectorAll('.col-resizer, .col-dragger').forEach((node) => node.remove());
  const text = (clone.textContent ?? '').replace(/\s+/g, ' ').trim();
  if (text) {
    return text;
  }
  const fallbackIndex = Number(header.dataset.originalIndex ?? '0') + 1;
  return `Column ${fallbackIndex}`;
}

function buildColumnOptions(
  headers: HTMLTableCellElement[],
  hiddenColumns: Set<number>
): ColumnOption[] {
  return headers.map((header, position) => {
    const parsed = Number(header.dataset.originalIndex ?? position);
    const originalIndex = Number.isInteger(parsed) && parsed >= 0 ? parsed : position;
    const label = header.dataset.columnLabel?.trim() || extractHeaderLabel(header);
    return {
      originalIndex,
      label,
      hidden: hiddenColumns.has(originalIndex)
    };
  });
}

function applyHiddenColumns(table: HTMLTableElement, hiddenColumns: Set<number>): void {
  const headerRow = table.tHead?.rows?.[0];
  if (!headerRow) {
    return;
  }
  const headers = Array.from(headerRow.cells) as HTMLTableCellElement[];
  const rows = Array.from(table.rows) as HTMLTableRowElement[];

  rows.forEach((row) => {
    const cells = Array.from(row.cells) as HTMLTableCellElement[];
    cells.forEach((cell, index) => {
      const header = headers[index];
      if (!header) {
        return;
      }
      const parsed = Number(header.dataset.originalIndex ?? index);
      const originalIndex = Number.isInteger(parsed) && parsed >= 0 ? parsed : index;
      const shouldHide = hiddenColumns.has(originalIndex);
      cell.style.display = shouldHide ? 'none' : '';
    });
  });
}

function originalIndexForHeader(header: HTMLTableCellElement, fallback: number): number {
  const parsed = Number(header.dataset.originalIndex ?? fallback);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function wrapperWidth(wrapper: HTMLDivElement | null, table: HTMLTableElement): number {
  if (wrapper) {
    const width = Math.round(wrapper.getBoundingClientRect().width);
    if (Number.isFinite(width) && width > 0) {
      return width;
    }
  }
  const tableWidth = Math.round(table.getBoundingClientRect().width);
  return Number.isFinite(tableWidth) && tableWidth > 0 ? tableWidth : 0;
}

function autoResizeVisibleColumns(
  headers: HTMLTableCellElement[],
  hiddenColumns: Set<number>,
  containerWidth: number,
  minColumnWidth: number,
  storedWidths: Record<string, number> | null
): void {
  const visibleHeaders = headers.filter((header, position) => !hiddenColumns.has(originalIndexForHeader(header, position)));
  if (visibleHeaders.length === 0) {
    return;
  }

  const targetTotal = Math.max(1, Math.floor(containerWidth));
  const perColumnBudget = Math.max(1, Math.floor(targetTotal / visibleHeaders.length));
  const effectiveMinWidth = Math.max(1, Math.min(minColumnWidth, perColumnBudget));
  const fallbackWidth = perColumnBudget;

  const basisWidths = visibleHeaders.map((header, position) => {
    const key = header.dataset.originalIndex ?? String(position);
    const stored = storedWidths ? storedWidths[key] : undefined;
    if (stored != null && Number.isFinite(stored) && stored > 0) {
      return Math.max(1, Math.round(stored));
    }
    return fallbackWidth;
  });

  const basisTotal = basisWidths.reduce((sum, width) => sum + width, 0);
  const safeBasisTotal = basisTotal > 0 ? basisTotal : fallbackWidth * visibleHeaders.length;
  const scale = targetTotal / safeBasisTotal;

  const scaled = basisWidths.map((width) => Math.max(effectiveMinWidth, Math.floor(width * scale)));
  let scaledTotal = scaled.reduce((sum, width) => sum + width, 0);

  if (scaledTotal > targetTotal) {
    let overflow = scaledTotal - targetTotal;
    while (overflow > 0) {
      let reduced = false;
      for (let index = scaled.length - 1; index >= 0 && overflow > 0; index -= 1) {
        if (scaled[index] > effectiveMinWidth) {
          scaled[index] -= 1;
          overflow -= 1;
          reduced = true;
        }
      }
      if (!reduced) {
        break;
      }
    }
    scaledTotal = scaled.reduce((sum, width) => sum + width, 0);
  }

  if (scaledTotal < targetTotal) {
    let remaining = targetTotal - scaledTotal;
    let index = 0;
    while (remaining > 0) {
      scaled[index % scaled.length] += 1;
      remaining -= 1;
      index += 1;
    }
  }

  const finalTotal = scaled.reduce((sum, width) => sum + width, 0);
  if (finalTotal > targetTotal) {
    const lastIndex = scaled.length - 1;
    scaled[lastIndex] = Math.max(1, scaled[lastIndex] - (finalTotal - targetTotal));
  }

  visibleHeaders.forEach((header, index) => {
    header.style.width = `${scaled[index]}px`;
  });
}

export function ResizableTable({ storageKey, children, minColumnWidth = 96 }: Props) {
  const wrapperRef = React.useRef<HTMLDivElement | null>(null);
  const tableRef = React.useRef<HTMLTableElement | null>(null);
  const hiddenColumnsRef = React.useRef<Set<number>>(new Set());
  const [columns, setColumns] = React.useState<ColumnOption[]>([]);
  const [menuOpen, setMenuOpen] = React.useState(false);

  React.useEffect(() => {
    if (!menuOpen) {
      return;
    }
    const onPointerDown = (event: MouseEvent): void => {
      const target = event.target as Node | null;
      if (!target) {
        return;
      }
      if (!wrapperRef.current?.contains(target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [menuOpen]);

  React.useEffect(() => {
    const table = tableRef.current;
    const headerRow = table?.tHead?.rows?.[0];
    if (!table || !headerRow) {
      return;
    }

    const initialHeaders = Array.from(headerRow.cells) as HTMLTableCellElement[];
    if (initialHeaders.length === 0) {
      return;
    }

    table.classList.add('resizable-table');
    initialHeaders.forEach((header, index) => {
      header.dataset.originalIndex = String(index);
      header.dataset.columnLabel = extractHeaderLabel(header);
    });

    const storedOrder = readStoredOrder(storageKey);
    if (isValidOrder(storedOrder, initialHeaders.length)) {
      applyColumnOrder(table, storedOrder);
    }

    const headers = Array.from(headerRow.cells) as HTMLTableCellElement[];
    const storedWidths = readStoredWidths(storageKey);

    let hiddenColumns = readStoredHidden(storageKey, headers.length);
    const hadStoredHiddenPreference = hasStoredHiddenPreference(storageKey);
    const defaultHidden = defaultHiddenColumns(headers);
    const appliedDefaultHidden = readStoredDefaultHiddenApplied(storageKey, headers.length);

    if (defaultHidden.size > 0) {
      let hiddenChanged = false;
      defaultHidden.forEach((columnIndex) => {
        if (!appliedDefaultHidden.has(columnIndex)) {
          hiddenColumns.add(columnIndex);
          appliedDefaultHidden.add(columnIndex);
          hiddenChanged = true;
        }
      });
      if (hiddenChanged || !hadStoredHiddenPreference) {
        writeStoredHidden(storageKey, hiddenColumns);
      }
      writeStoredDefaultHiddenApplied(storageKey, appliedDefaultHidden);
    } else if (!hadStoredHiddenPreference) {
      writeStoredHidden(storageKey, hiddenColumns);
    }
    if (hiddenColumns.size >= headers.length) {
      hiddenColumns = new Set();
      writeStoredHidden(storageKey, hiddenColumns);
    }
    hiddenColumnsRef.current = hiddenColumns;

    const removeListeners: Array<() => void> = [];
    let draggedHeader: HTMLTableCellElement | null = null;

    headers.forEach((header) => {
      header.classList.add('resizable-header');
      header.querySelectorAll(':scope > .col-resizer, :scope > .col-dragger').forEach((node) => node.remove());
    });

    const getHeaderCells = (): HTMLTableCellElement[] => Array.from(headerRow.cells) as HTMLTableCellElement[];

    const syncColumnState = (): void => {
      const currentHeaders = getHeaderCells();
      applyHiddenColumns(table, hiddenColumnsRef.current);
      setColumns(buildColumnOptions(currentHeaders, hiddenColumnsRef.current));
    };

    const rebalanceWidths = (): void => {
      const currentHeaders = getHeaderCells();
      const width = wrapperWidth(wrapperRef.current, table);
      autoResizeVisibleColumns(currentHeaders, hiddenColumnsRef.current, width, minColumnWidth, readStoredWidths(storageKey));
      writeStoredWidths(storageKey, currentHeaders);
    };

    applyHiddenColumns(table, hiddenColumnsRef.current);
    rebalanceWidths();

    headers.forEach((header) => {
      const handle = document.createElement('div');
      handle.className = 'col-resizer';
      header.appendChild(handle);

      const onMouseDown = (event: MouseEvent): void => {
        event.preventDefault();
        const startX = event.clientX;
        const startWidth = header.getBoundingClientRect().width;

        const onMove = (moveEvent: MouseEvent): void => {
          const delta = moveEvent.clientX - startX;
          const nextWidth = Math.max(minColumnWidth, startWidth + delta);
          header.style.width = `${nextWidth}px`;
        };

        const onUp = (): void => {
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
          writeStoredWidths(storageKey, getHeaderCells());
          rebalanceWidths();
        };

        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      };

      handle.addEventListener('mousedown', onMouseDown);
      removeListeners.push(() => handle.removeEventListener('mousedown', onMouseDown));

      const dragger = document.createElement('button');
      dragger.className = 'col-dragger';
      dragger.type = 'button';
      dragger.textContent = '⋮⋮';
      dragger.title = 'Drag to reorder column';
      dragger.setAttribute('aria-label', 'Drag to reorder column');
      dragger.draggable = true;
      header.appendChild(dragger);

      const onDragStart = (event: DragEvent): void => {
        draggedHeader = header;
        header.classList.add('is-dragging');
        if (event.dataTransfer) {
          event.dataTransfer.effectAllowed = 'move';
          event.dataTransfer.setData('text/plain', 'column');
        }
      };

      const onDragEnd = (): void => {
        header.classList.remove('is-dragging');
        getHeaderCells().forEach((cell) => cell.classList.remove('drop-target'));
        draggedHeader = null;
      };

      const onDragOver = (event: DragEvent): void => {
        if (!draggedHeader || draggedHeader === header) {
          return;
        }
        event.preventDefault();
        header.classList.add('drop-target');
      };

      const onDragLeave = (): void => {
        header.classList.remove('drop-target');
      };

      const onDrop = (event: DragEvent): void => {
        if (!draggedHeader) {
          return;
        }
        event.preventDefault();
        const currentHeaders = getHeaderCells();
        const fromIndex = currentHeaders.indexOf(draggedHeader);
        const toIndex = currentHeaders.indexOf(header);
        if (fromIndex >= 0 && toIndex >= 0 && fromIndex !== toIndex) {
          moveColumn(table, fromIndex, toIndex);
          const nextHeaders = getHeaderCells();
          autoResizeVisibleColumns(
            nextHeaders,
            hiddenColumnsRef.current,
            wrapperWidth(wrapperRef.current, table),
            minColumnWidth,
            readStoredWidths(storageKey)
          );
          writeStoredOrder(storageKey, nextHeaders);
          writeStoredWidths(storageKey, nextHeaders);
        }
        currentHeaders.forEach((cell) => cell.classList.remove('drop-target'));
        syncColumnState();
      };

      dragger.addEventListener('dragstart', onDragStart);
      dragger.addEventListener('dragend', onDragEnd);
      header.addEventListener('dragover', onDragOver);
      header.addEventListener('dragleave', onDragLeave);
      header.addEventListener('drop', onDrop);
      removeListeners.push(() => dragger.removeEventListener('dragstart', onDragStart));
      removeListeners.push(() => dragger.removeEventListener('dragend', onDragEnd));
      removeListeners.push(() => header.removeEventListener('dragover', onDragOver));
      removeListeners.push(() => header.removeEventListener('dragleave', onDragLeave));
      removeListeners.push(() => header.removeEventListener('drop', onDrop));
    });

    syncColumnState();

    const onResize = (): void => {
      rebalanceWidths();
    };
    window.addEventListener('resize', onResize);

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && wrapperRef.current) {
      resizeObserver = new ResizeObserver(() => rebalanceWidths());
      resizeObserver.observe(wrapperRef.current);
    }

    return () => {
      window.removeEventListener('resize', onResize);
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
      removeListeners.forEach((remove) => remove());
      getHeaderCells().forEach((header) => {
        header.querySelectorAll(':scope > .col-resizer, :scope > .col-dragger').forEach((node) => node.remove());
        header.classList.remove('is-dragging');
        header.classList.remove('drop-target');
      });
    };
  }, [children, storageKey, minColumnWidth]);

  const toggleColumn = React.useCallback((originalIndex: number): void => {
    const table = tableRef.current;
    const headerRow = table?.tHead?.rows?.[0];
    if (!table || !headerRow) {
      return;
    }
    const headers = Array.from(headerRow.cells) as HTMLTableCellElement[];
    const nextHidden = new Set(hiddenColumnsRef.current);
    const isHidden = nextHidden.has(originalIndex);

    if (isHidden) {
      nextHidden.delete(originalIndex);
    } else {
      const visibleCount = headers.filter((header, position) => {
        const parsed = Number(header.dataset.originalIndex ?? position);
        const currentIndex = Number.isInteger(parsed) && parsed >= 0 ? parsed : position;
        return !nextHidden.has(currentIndex);
      }).length;
      if (visibleCount <= 1) {
        return;
      }
      nextHidden.add(originalIndex);
    }

    hiddenColumnsRef.current = nextHidden;
    writeStoredHidden(storageKey, nextHidden);
    applyHiddenColumns(table, nextHidden);
    autoResizeVisibleColumns(
      headers,
      nextHidden,
      wrapperWidth(wrapperRef.current, table),
      minColumnWidth,
      readStoredWidths(storageKey)
    );
    writeStoredWidths(storageKey, headers);
    setColumns(buildColumnOptions(headers, nextHidden));
  }, [storageKey, minColumnWidth]);

  return (
    <div className="resizable-table-wrapper" ref={wrapperRef}>
      <div className="table-column-controls">
        <button
          type="button"
          className="table-settings-btn"
          onClick={() => setMenuOpen((current) => !current)}
          aria-label="Show or hide columns"
          title="Show or hide columns"
          disabled={columns.length === 0}
        >
          ⚙
        </button>
        {menuOpen && columns.length > 0 && (
          <div className="table-settings-menu" role="menu" aria-label="Column visibility">
            <div className="table-settings-title">Columns</div>
            {columns.map((column) => {
              const visibleCount = columns.filter((item) => !item.hidden).length;
              const disableHide = !column.hidden && visibleCount <= 1;
              return (
                <label key={column.originalIndex} className="table-settings-item">
                  <input
                    type="checkbox"
                    checked={!column.hidden}
                    onChange={() => toggleColumn(column.originalIndex)}
                    disabled={disableHide}
                  />
                  <span>{column.label}</span>
                </label>
              );
            })}
          </div>
        )}
      </div>
      <table ref={tableRef}>
        {children}
      </table>
    </div>
  );
}
