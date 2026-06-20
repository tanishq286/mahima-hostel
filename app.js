/* ============================================================
 * Mahima Hostel - app.js
 * DEVELOPER NOTES:
 *   - WHATSAPP_NUMBER: change here to update the WhatsApp target
 *   - galleryMedia: add or remove gallery items (images & videos)
 *     - type: "image" or "video"
 *     - category: "rooms" or "facilities" (matches filter buttons)
 *     - src: path to the file
 *     - poster (videos only): optional preview image
 *     - alt: accessible label / caption
 * ============================================================ */

const WHATSAPP_NUMBER = '918209810772';

/* ------------------------------------------------------------
 * Gallery media — loaded from gallery.json at runtime.
 * Manage items via admin.html (client) or edit gallery.json
 * directly in the repo (developer). The list below is only a
 * fallback if gallery.json fails to load.
 * ------------------------------------------------------------ */
let galleryMedia = [
  { type: 'image', category: 'rooms',      src: 'assets/room_single.png',  alt: 'Single Sharing Room Interior' },
  { type: 'image', category: 'rooms',      src: 'assets/room_double.png',  alt: 'Double Sharing Room Interior' },
  { type: 'image', category: 'facilities', src: 'assets/mess.png',         alt: 'Clean Student Mess Dining' },
  { type: 'image', category: 'facilities', src: 'assets/gym.png',          alt: 'On-site Gym Facility' },
  // Example video entry (uncomment and replace src with a real video file):
  // { type: 'video', category: 'facilities', src: 'assets/tour.mp4', poster: 'assets/mess.png', alt: 'PG Walkthrough Video' },
];

document.addEventListener('DOMContentLoaded', () => {

  /* ----- 1. Header scroll styling ----- */
  const header = document.getElementById('header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) header.classList.add('scrolled');
    else header.classList.remove('scrolled');
  });

  /* ----- 2. Mobile menu toggle ----- */
  const mobileMenuBtn = document.getElementById('mobile-menu-btn');
  const navLinks = document.getElementById('nav-links');
  const navLinksList = document.querySelectorAll('.nav-link');

  const toggleMenu = (forceClose) => {
    const spans = mobileMenuBtn.querySelectorAll('span');
    if (forceClose || navLinks.classList.contains('open')) {
      navLinks.classList.remove('open');
      mobileMenuBtn.classList.remove('active');
      spans[0].style.transform = 'none';
      spans[1].style.opacity = '1';
      spans[2].style.transform = 'none';
    } else {
      navLinks.classList.add('open');
      mobileMenuBtn.classList.add('active');
      spans[0].style.transform = 'rotate(45deg) translate(5px, 6px)';
      spans[1].style.opacity = '0';
      spans[2].style.transform = 'rotate(-45deg) translate(5px, -6px)';
    }
  };

  mobileMenuBtn.addEventListener('click', () => toggleMenu(false));
  navLinksList.forEach(link => link.addEventListener('click', () => toggleMenu(true)));

  /* ----- 3. Render gallery + filtering ----- */
  const galleryGrid = document.getElementById('gallery-grid');
  const filterBtns = document.querySelectorAll('.filter-btn');

  const renderGallery = (filter = 'all') => {
    galleryGrid.innerHTML = '';
    galleryMedia.forEach((media, index) => {
      if (filter !== 'all' && media.category !== filter) return;
      const item = document.createElement('div');
      item.className = 'gallery-item';
      item.dataset.category = media.category;
      item.dataset.index = index;
      item.setAttribute('role', 'button');
      item.setAttribute('tabindex', '0');
      item.setAttribute('aria-label', `Open ${media.alt}`);

      if (media.type === 'video') {
        item.innerHTML = `
          <video src="${media.src}" ${media.poster ? `poster="${media.poster}"` : ''} muted playsinline></video>
          <div class="gallery-overlay">
            <span class="gallery-video-tag">▶ Video</span>
          </div>`;
      } else {
        item.innerHTML = `
          <img src="${media.src}" alt="${media.alt}" loading="lazy">
          <div class="gallery-overlay">
            <svg class="gallery-zoom-icon" xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
            </svg>
          </div>`;
      }

      item.addEventListener('click', () => openLightbox(index, filter));
      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openLightbox(index, filter); }
      });
      galleryGrid.appendChild(item);
    });
  };

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderGallery(btn.dataset.filter);
    });
  });

  renderGallery('all');

  // Load gallery from Vercel Blob API, fall back to repo gallery.json
  const applyGallery = (data) => {
    if (Array.isArray(data.items) && data.items.length) {
      galleryMedia = data.items;
      const activeFilter = document.querySelector('.filter-btn.active');
      renderGallery(activeFilter ? activeFilter.dataset.filter : 'all');
    }
  };

  fetch('/api/gallery', { cache: 'no-store' })
    .then(res => res.ok ? res.json() : Promise.reject())
    .then(data => {
      if (data.items && data.items.length) { applyGallery(data); return; }
      throw new Error('empty');
    })
    .catch(() =>
      fetch('gallery.json', { cache: 'no-store' })
        .then(res => res.ok ? res.json() : Promise.reject())
        .then(applyGallery)
        .catch(() => { /* keep hardcoded fallback */ })
    );

  /* ----- 4. Lightbox ----- */
  const lightbox = document.getElementById('lightbox');
  const lightboxContent = document.getElementById('lightbox-content');
  const lightboxCounter = document.getElementById('lightbox-counter');
  let lightboxItems = [];
  let lightboxIndex = 0;

  const renderLightbox = () => {
    const media = lightboxItems[lightboxIndex];
    if (!media) return;
    if (media.type === 'video') {
      lightboxContent.innerHTML = `<video src="${media.src}" ${media.poster ? `poster="${media.poster}"` : ''} controls autoplay playsinline></video>`;
    } else {
      lightboxContent.innerHTML = `<img src="${media.src}" alt="${media.alt}">`;
    }
    lightboxCounter.textContent = `${lightboxIndex + 1} / ${lightboxItems.length}`;
  };

  const openLightbox = (globalIndex, filter) => {
    lightboxItems = filter === 'all' || !filter
      ? galleryMedia.slice()
      : galleryMedia.filter(m => m.category === filter);
    const target = galleryMedia[globalIndex];
    lightboxIndex = Math.max(0, lightboxItems.indexOf(target));
    lightbox.classList.add('open');
    lightbox.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    renderLightbox();
  };

  const closeLightbox = () => {
    lightbox.classList.remove('open');
    lightbox.setAttribute('aria-hidden', 'true');
    lightboxContent.innerHTML = '';
    document.body.style.overflow = '';
  };

  const nextLightbox = () => {
    lightboxIndex = (lightboxIndex + 1) % lightboxItems.length;
    renderLightbox();
  };

  const prevLightbox = () => {
    lightboxIndex = (lightboxIndex - 1 + lightboxItems.length) % lightboxItems.length;
    renderLightbox();
  };

  lightbox.querySelectorAll('[data-lightbox-close]').forEach(el => el.addEventListener('click', closeLightbox));
  lightbox.querySelector('[data-lightbox-next]').addEventListener('click', nextLightbox);
  lightbox.querySelector('[data-lightbox-prev]').addEventListener('click', prevLightbox);
  lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); });

  document.addEventListener('keydown', (e) => {
    if (!lightbox.classList.contains('open')) return;
    if (e.key === 'Escape') closeLightbox();
    else if (e.key === 'ArrowRight') nextLightbox();
    else if (e.key === 'ArrowLeft') prevLightbox();
  });

  /* ----- 5. Testimonials slider ----- */
  const slides = document.querySelectorAll('.testimonial-slide');
  const dots = document.querySelectorAll('.slider-dot');
  let currentSlide = 0;
  let slideInterval;

  const showSlide = (index) => {
    slides.forEach(slide => slide.classList.remove('active'));
    dots.forEach(dot => dot.classList.remove('active'));
    slides[index].classList.add('active');
    dots[index].classList.add('active');
    currentSlide = index;
  };

  const nextSlide = () => showSlide((currentSlide + 1) % slides.length);
  const startSlideShow = () => { slideInterval = setInterval(nextSlide, 5000); };
  const stopSlideShow = () => clearInterval(slideInterval);

  dots.forEach(dot => {
    dot.addEventListener('click', () => {
      stopSlideShow();
      showSlide(parseInt(dot.getAttribute('data-index'), 10));
      startSlideShow();
    });
  });

  startSlideShow();

  /* ----- 6. FAQ accordion ----- */
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach(item => {
    const question = item.querySelector('.faq-question');
    const answer = item.querySelector('.faq-answer');
    question.addEventListener('click', () => {
      const isActive = item.classList.contains('active');
      faqItems.forEach(other => {
        other.classList.remove('active');
        other.querySelector('.faq-answer').style.maxHeight = '0';
      });
      if (!isActive) {
        item.classList.add('active');
        answer.style.maxHeight = answer.scrollHeight + 'px';
      }
    });
  });

  /* ----- 7. Enquiry Modal ----- */
  const enquiryModal = document.getElementById('enquiry-modal');
  const enquiryForm = document.getElementById('enquiry-form');
  const roomSelect = document.getElementById('enq-room');
  const toast = document.getElementById('toast');
  const toastMessage = document.getElementById('toast-message');
  let lastFocused = null;

  const openEnquiry = (preselectRoom) => {
    lastFocused = document.activeElement;
    enquiryModal.classList.add('open');
    enquiryModal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    if (preselectRoom) roomSelect.value = preselectRoom;
    setTimeout(() => document.getElementById('enq-name').focus(), 50);
  };

  const closeEnquiry = () => {
    enquiryModal.classList.remove('open');
    enquiryModal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (lastFocused) lastFocused.focus();
  };

  document.querySelectorAll('[data-enquiry-trigger]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      openEnquiry(btn.dataset.room || '');
    });
  });

  enquiryModal.querySelectorAll('[data-modal-close]').forEach(el => el.addEventListener('click', closeEnquiry));

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && enquiryModal.classList.contains('open')) closeEnquiry();
  });

  const showToast = (message, type = 'success') => {
    toastMessage.textContent = message;
    toast.dataset.type = type;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3500);
  };

  const setError = (field, message) => {
    const el = enquiryForm.querySelector(`[data-error-for="${field}"]`);
    if (el) el.textContent = message || '';
    const input = enquiryForm.querySelector(`[name="${field}"]`);
    if (input) input.classList.toggle('has-error', !!message);
  };

  enquiryForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(enquiryForm).entries());
    let valid = true;

    setError('name', '');
    setError('phone', '');

    if (!data.name || data.name.trim().length < 2) {
      setError('name', 'Please enter your full name.'); valid = false;
    }
    const phoneDigits = (data.phone || '').replace(/\D/g, '');
    if (phoneDigits.length < 10) {
      setError('phone', 'Enter a valid 10-digit phone number.'); valid = false;
    }
    if (!valid) return;

    const roomLabel = {
      single: 'Single Sharing',
      double: 'Double Sharing',
    }[data.room] || 'Not specified';

    const lines = [
      '*New Enquiry — Mahima Hostel*',
      '',
      `*Name:* ${data.name}`,
      `*Phone:* ${data.phone}`,
    ];
    if (data.email)   lines.push(`*Email:* ${data.email}`);
    lines.push(`*Preferred Room:* ${roomLabel}`);
    if (data.date)    lines.push(`*Move-in Date:* ${data.date}`);
    if (data.message) lines.push('', `*Message:* ${data.message}`);

    const url = `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(lines.join('\n'))}`;
    window.open(url, '_blank', 'noopener');

    enquiryForm.reset();
    closeEnquiry();
    showToast('Opening WhatsApp with your enquiry...');
  });

  /* ----- 8. Active nav highlighting ----- */
  const sectionIds = ['hero', 'about', 'rooms', 'amenities', 'gallery', 'testimonials', 'faq', 'contact'];
  const sectionEls = sectionIds.map(id => document.getElementById(id)).filter(Boolean);
  const navLinkMap = {};
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href') || '';
    const id = href.startsWith('#') ? href.slice(1) : '';
    if (id) navLinkMap[id] = link;
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        Object.values(navLinkMap).forEach(l => l.classList.remove('active'));
        const link = navLinkMap[entry.target.id];
        if (link) link.classList.add('active');
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px', threshold: 0 });

  sectionEls.forEach(s => observer.observe(s));
});
