/**
 * HADES Auth — Form validation effects
 */
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('signupForm');
    if (!form) return;

    form.addEventListener('submit', (e) => {
        const pass = document.getElementById('password').value;
        const confirm = document.getElementById('confirm_password').value;

        if (pass !== confirm) {
            e.preventDefault();
            alert('Passwords do not match!');
            return;
        }

        if (pass.length < 6) {
            e.preventDefault();
            alert('Password must be at least 6 characters.');
            return;
        }
    });

    // Input focus glow effects
    document.querySelectorAll('.input-wrapper input').forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.borderColor = '#00f0ff';
        });
        input.addEventListener('blur', () => {
            input.parentElement.style.borderColor = '';
        });
    });
});
