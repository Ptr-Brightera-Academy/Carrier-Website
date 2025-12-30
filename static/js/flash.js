  const toggleBtn = document.getElementById('theme-toggle');
  toggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    document.body.classList.toggle('light-mode');
  });

document.addEventListener("DOMContentLoaded", function() {
    const flash = document.querySelector('.alert');
    if(flash) {
        // Auto hide 
        setTimeout(function() {
            flash.style.display = 'none';
        }, 3000);
    }
});

setTimeout(() => {
  const errors = document.querySelectorAll('.auto-hide-error');
  errors.forEach(err => err.remove());
}, 5000);