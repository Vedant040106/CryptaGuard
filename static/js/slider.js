// Select all panels
const panels = document.querySelectorAll('.panel');

// Add click listener to each
panels.forEach(panel => {
    panel.addEventListener('click', (e) => {
        // If clicking the already active panel, do nothing (or we could launch the module)
        if(panel.classList.contains('active')) return;

        removeActiveClasses();
        panel.classList.add('active');
        
        // Optional: Play a sound effect here if you wanted
    });
    
    // Add mouseenter for "Peek" sound logic or advanced JS hovers if needed
});

function removeActiveClasses() {
    panels.forEach(panel => {
        panel.classList.remove('active');
    });
}