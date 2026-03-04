const products = [
  { id: "p-100", name: "Wireless Mouse", price: 19.99, category: "Accessories" },
  { id: "p-101", name: "Notebook Set", price: 12.5, category: "Office" },
  { id: "p-102", name: "USB-C Hub", price: 34.0, category: "Electronics" },
  { id: "p-103", name: "Desk Lamp", price: 27.75, category: "Home" },
  { id: "p-104", name: "Water Bottle", price: 15.0, category: "Lifestyle" },
  { id: "p-105", name: "Bluetooth Speaker", price: 42.0, category: "Electronics" }
];

let cartCount = 0;

function renderProducts(items) {
  const grid = document.getElementById("productGrid");
  grid.innerHTML = "";
  for (const item of items) {
    const card = document.createElement("article");
    card.className = "product";
    card.innerHTML = `
      <p class="small">${item.category}</p>
      <h3>${item.name}</h3>
      <p>$${item.price.toFixed(2)}</p>
      <button type="button" data-id="${item.id}">Add to Cart</button>
    `;
    grid.appendChild(card);
  }
}

function updateCartLabel() {
  const cartBtn = document.getElementById("cartBtn");
  cartBtn.textContent = `Cart (${cartCount})`;
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-id]");
  if (!button) {
    return;
  }
  cartCount += 1;
  updateCartLabel();
});

document.getElementById("searchForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const query = document.getElementById("searchInput").value.trim().toLowerCase();
  const filtered = query
    ? products.filter((item) => item.name.toLowerCase().includes(query) || item.category.toLowerCase().includes(query))
    : products;
  renderProducts(filtered);
  document.getElementById("searchMsg").textContent = `${filtered.length} result(s) for "${query || "all"}".`;
});

document.getElementById("newsletterForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const email = document.getElementById("newsletterEmail").value.trim();
  document.getElementById("newsletterMsg").textContent = `Subscribed ${email} to weekly deal alerts.`;
  event.target.reset();
});

document.getElementById("supportForm").addEventListener("submit", (event) => {
  event.preventDefault();
  document.getElementById("supportMsg").textContent = "Thanks. Your support message has been queued.";
  event.target.reset();
});

renderProducts(products);
updateCartLabel();
