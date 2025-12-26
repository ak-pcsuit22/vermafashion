// Minimal JS placeholder
console.log('Verma Fashions frontend loaded');

// small helper to POST JSON
async function postJSON(url, data){
	const res = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
	return res.json();
}

// Mobile nav toggle
(() => {
	const btn = document.querySelector('.nav-toggle');
	const body = document.body;
	const nav = document.getElementById('site-nav');
	if (!btn || !nav) return;
	function openNav(){
		body.classList.add('nav-open');
		btn.setAttribute('aria-expanded','true');
	}
	function closeNav(){
		body.classList.remove('nav-open');
		btn.setAttribute('aria-expanded','false');
	}
	btn.addEventListener('click', (e)=>{
		if (body.classList.contains('nav-open')) closeNav(); else openNav();
	});
	// close when a nav link is clicked
	nav.addEventListener('click', (e)=>{
		if (e.target && e.target.tagName === 'A') closeNav();
	});
	// close on Escape
	document.addEventListener('keydown', (e)=>{ if (e.key === 'Escape') closeNav(); });
	// close when clicking outside nav (detect overlay click)
	document.addEventListener('click', (e)=>{
		if (!body.classList.contains('nav-open')) return;
		if (!nav.contains(e.target) && !btn.contains(e.target)) closeNav();
	}, true);
})();

// Enhance add-to-cart forms: submit via AJAX and show "Go to cart" button
(() => {
	// find add-to-cart forms (progressive enhancement)
	const forms = Array.from(document.querySelectorAll('form[action$="/cart/add"]'));
	if (!forms.length) return;

	function showGoToCartToast(qty) {
		// remove existing toast if any
		const existing = document.getElementById('go-to-cart-toast');
		if (existing) existing.remove();

		const el = document.createElement('div');
		el.id = 'go-to-cart-toast';
		el.className = 'go-to-cart-toast';
		el.innerHTML = `<div class="toast-text">Added ${qty} to cart</div><a class="toast-btn" href="/cart">Go to cart</a>`;
		document.body.appendChild(el);
		// auto remove after 6s
		setTimeout(() => el.remove(), 6000);
	}

	function updateCartCount(delta) {
		try {
			const links = Array.from(document.querySelectorAll('a[href$="/cart"]'));
			if (!links.length) return;
			links.forEach(a => {
				const txt = a.textContent || '';
				// match a number inside parentheses
				const m = txt.match(/\((\d+)\)/);
				if (m) {
					const n = parseInt(m[1], 10) + delta;
					a.textContent = txt.replace(/\(\d+\)/, `(${n})`);
				} else {
					// append count
					a.textContent = txt + ` (${delta})`;
				}
			});
		} catch (e) { /* ignore */ }
	}

	forms.forEach(f => {
		f.addEventListener('submit', async function (ev) {
			// progressive enhancement: perform AJAX submit and show toast
			try {
				ev.preventDefault();
				const fd = new FormData(f);
				const qty = parseInt(fd.get('quantity') || '1', 10) || 1;
				const resp = await fetch(f.action, { method: 'POST', body: fd, credentials: 'same-origin' });
				if (resp.ok) {
					showGoToCartToast(qty);
					updateCartCount(qty);
				} else {
					// fallback to normal submit on server error
					f.submit();
				}
			} catch (e) {
				// on network errors, fallback to normal submit
				f.submit();
			}
		});
	});
})();
