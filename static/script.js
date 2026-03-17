document.querySelectorAll("input").forEach(input => {
    input.addEventListener("focus", function(){
        this.style.background = "#e0f7ff";
    });
    
    input.addEventListener("blur", function(){
        this.style.background = "#fff";
    });
});