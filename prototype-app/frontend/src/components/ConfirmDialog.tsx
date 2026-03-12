import React from 'react';

type Props = {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({ isOpen, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', onConfirm, onCancel }: Props) {
  const dialogRef = React.useRef<HTMLDialogElement>(null);

  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (isOpen) {
      if (!dialog.open) dialog.showModal();
    } else {
      if (dialog.open) dialog.close();
    }
  }, [isOpen]);

  // Close on backdrop click
  function handleDialogClick(event: React.MouseEvent<HTMLDialogElement>): void {
    if (event.target === dialogRef.current) onCancel();
  }

  if (!isOpen) return null;

  return (
    <dialog
      ref={dialogRef}
      className="confirm-dialog"
      onClick={handleDialogClick}
      onCancel={onCancel}
    >
      <div className="confirm-dialog-content">
        <h4 className="confirm-dialog-title">{title}</h4>
        <p className="confirm-dialog-message">{message}</p>
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button type="button" className="btn btn-primary" onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </dialog>
  );
}
