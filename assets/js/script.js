/**
 * ====================================================================
 * Secure Task Management System
 * Client-Side JavaScript Module
 * 
 * Capabilities:
 * - Client-side form validation (Pass matching, title checks).
 * - Modal management (Add Task, Delete Confirmation).
 * - Auto-dismissing flash alerts.
 * - CSRF token verification support.
 * ====================================================================
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Flash alert auto-dismissal
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function (alert) {
        const closeBtn = alert.querySelector('.alert-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', function () {
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 200);
            });
        }
        // Auto dismiss after 6 seconds for non-error alerts
        if (!alert.classList.contains('alert-danger')) {
            setTimeout(function () {
                alert.style.transition = 'opacity 0.4s ease';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 400);
            }, 6000);
        }
    });

    // 2. Registration Form Password Match Validation
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const passwordInput = document.getElementById('password');
        const confirmInput = document.getElementById('confirm_password');
        const matchError = document.getElementById('passwordMatchError');

        function validatePasswordMatch() {
            if (confirmInput.value && passwordInput.value !== confirmInput.value) {
                if (matchError) matchError.style.display = 'block';
                confirmInput.setCustomValidity("Passwords do not match");
            } else {
                if (matchError) matchError.style.display = 'none';
                confirmInput.setCustomValidity("");
            }
        }

        if (passwordInput && confirmInput) {
            passwordInput.addEventListener('input', validatePasswordMatch);
            confirmInput.addEventListener('input', validatePasswordMatch);
        }
    }

    // 3. Modal Handlers
    const modalTriggers = document.querySelectorAll('[data-modal-target]');
    modalTriggers.forEach(function (trigger) {
        trigger.addEventListener('click', function (e) {
            e.preventDefault();
            const modalId = trigger.getAttribute('data-modal-target');
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.add('active');
            }
        });
    });

    const modalCloses = document.querySelectorAll('[data-modal-close]');
    modalCloses.forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            const modal = btn.closest('.modal-overlay');
            if (modal) {
                modal.classList.remove('active');
            }
        });
    });

    // Close modal when clicking on backdrop
    const modals = document.querySelectorAll('.modal-overlay');
    modals.forEach(function (modal) {
        modal.addEventListener('click', function (e) {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

    // 4. Secure Delete Confirmation
    const deleteButtons = document.querySelectorAll('.btn-delete-task');
    const deleteModal = document.getElementById('deleteConfirmModal');
    const deleteForm = document.getElementById('deleteTaskForm');
    const deleteTaskIdInput = document.getElementById('deleteTaskId');
    const deleteTaskTitleDisplay = document.getElementById('deleteTaskTitle');

    deleteButtons.forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            const taskId = btn.getAttribute('data-task-id');
            const taskTitle = btn.getAttribute('data-task-title');

            if (deleteModal && deleteTaskIdInput && deleteTaskTitleDisplay) {
                deleteTaskIdInput.value = taskId;
                deleteTaskTitleDisplay.textContent = taskTitle;
                deleteModal.classList.add('active');
            } else {
                // Fallback standard confirm
                if (confirm(`Are you sure you want to delete task: "${taskTitle}"?`)) {
                    btn.closest('form').submit();
                }
            }
        });
    });

    // 5. Close modals on Escape key
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(function (modal) {
                modal.classList.remove('active');
            });
        }
    });
});

