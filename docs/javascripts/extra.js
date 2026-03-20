console.log("extra.js loaded");
function initImageZoom() {
  console.log("initImageZoom running");

  let lightbox = document.getElementById("image-lightbox");

  if (!lightbox) {
    lightbox = document.createElement("div");
    lightbox.id = "image-lightbox";
    lightbox.className = "image-lightbox";
    lightbox.innerHTML = `
      <div class="image-lightbox__backdrop"></div>
      <div class="image-lightbox__content">
        <button class="image-lightbox__close" aria-label="Close image">×</button>
        <img class="image-lightbox__img" alt="">
      </div>
    `;
    document.body.appendChild(lightbox);

    const close = () => lightbox.classList.remove("is-open");

    lightbox.querySelector(".image-lightbox__backdrop").addEventListener("click", close);
    lightbox.querySelector(".image-lightbox__close").addEventListener("click", close);

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") close();
    });
  }

  const lightboxImg = lightbox.querySelector(".image-lightbox__img");

  document.querySelectorAll("img.zoomable").forEach((img) => {
    if (img.dataset.zoomBound === "true") return;

    img.dataset.zoomBound = "true";

    img.addEventListener("click", () => {
      console.log("image clicked:", img.src);
      lightboxImg.src = img.src;
      lightboxImg.alt = img.alt || "";
      lightbox.classList.add("is-open");
    });
  });
}

if (window.document$ && typeof window.document$.subscribe === "function") {
  window.document$.subscribe(initImageZoom);
} else {
  document.addEventListener("DOMContentLoaded", initImageZoom);
}