(function () {
    const listEl = document.getElementById('feedList');
    const filterInput = document.getElementById('filterText');
    const applyFilterBtn = document.getElementById('applyFilterBtn');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const selectAllBtn = document.getElementById('selectAllBtn');
    const deleteBtn = document.getElementById('deleteBtn');
    const pageInfo = document.getElementById('pageInfo');
    const panel = document.getElementById('feed-panel');
    const pageCurrent = document.getElementById('pageCurrent');
    const headerSelectAll = document.getElementById('headerSelectAll');
    const sortTitleBtn = document.getElementById('sortTitleBtn');
    const sortDateBtn = document.getElementById('sortDateBtn');
    const sortChannelBtn = document.getElementById('sortChannelBtn');
    const tablist = document.getElementById('sidebarTabs');
    const PAGE_SIZE = 20;
    let currentPage = 0;
    let sortState = {key: 'date', dir: -1}; // dir: 1 asc, -1 desc. Default: newest first (date desc).
    const SESSION_HEADER = 'X-Session-Id';
    if (!tablist) return;
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const panels = new Map(
        Array.from(document.querySelectorAll('.tab-panel')).map(p => [p.id, p])
    );

    function activate(tabEl) {
        if (!tabEl) return;
        tabs.forEach(t => t.setAttribute('aria-selected', String(t === tabEl)));
        const targetId = tabEl.getAttribute('aria-controls');
        panels.forEach((panel, id) => {
            panel.setAttribute('aria-hidden', String(id !== targetId));
        });
        tabEl.focus();
    }

    tablist.addEventListener('click', (e) => {
        const btn = e.target.closest('[role="tab"]');
        if (btn) activate(btn);
    });

    tablist.addEventListener('keydown', (e) => {
        const currentIndex = tabs.findIndex(t => t.getAttribute('aria-selected') === 'true');
        if (currentIndex < 0) return;

        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            const dir = e.key === 'ArrowDown' ? 1 : -1;
            const next = tabs[(currentIndex + dir + tabs.length) % tabs.length];
            activate(next);
        } else if (e.key === 'Home') {
            e.preventDefault();
            activate(tabs[0]);
        } else if (e.key === 'End') {
            e.preventDefault();
            activate(tabs[tabs.length - 1]);
        } else if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            activate(tabs[currentIndex]);
        }
    });

    // Ensure initial activation reflects markup
    const initial = tabs.find(t => t.getAttribute('aria-selected') === 'true') || tabs[0];
    activate(initial);

    async function fetchWithSession(input, init = {}) {
        if (!window.session.sessionId) throw new Error("No session ID available!");
        init.headers = init.headers || {};
        init.headers[SESSION_HEADER] = window.session.sessionId;
        return fetch(input, init);
    }

    // DOM elements
    const channelsList = document.getElementById('channelsList');
    const myChannelsList = document.getElementById('myChannelsList');
    const feedTbody = document.getElementById('feedTbody');

    function el(tag, attrs = {}, children = []) {
        const node = document.createElement(tag);
        Object.entries(attrs).forEach(([k, v]) => {
            if (k === 'class') node.className = v;
            else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => node.dataset[dk] = dv);
            else if (k === 'text') node.textContent = v;
            else node.setAttribute(k, v);
        });
        children.forEach(c => node.appendChild(c));
        return node;
    }

    function safeText(v, fallback = '') {
        return v == null ? fallback : String(v);
    }

    function formatDateLabel(s) {
        const d = new Date(s);
        if (isNaN(d)) return s || '';
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        // Use UTC to avoid local timezone shifting dates if server returns Z/UTC
        return `${months[d.getUTCMonth()]} ${d.getUTCDate()}`;
    }

    // Render channels (subscriptions/creators)
    function renderMyChannels(items) {
        myChannelsList.innerHTML = '';
        if (!Array.isArray(items) || items.length === 0) {
            myChannelsList.appendChild(
                el('li', {class: 'channel-item'}, [
                    el('img', {class: 'channel-thumb', src: window.session.DEFAULT_THUMB, alt: 'Default channel thumbnail'}),
                    el('span', {class: 'channel-title', text: '{{ _("No channels yet") }}'})
                ])
            );
            return;
        }
        items.forEach(ch => {
            const channelId = ch.channel_id;
            const title = safeText(ch.title || '{{ _("Untitled") }}');
            const thumb = ch.thumbnail_url || window.session.DEFAULT_THUMB;
            myChannelsList.appendChild(
                el('li', {id: id, class: 'channel-item'}, [
                    el('img', {class: 'channel-thumb', src: thumb, alt: `${title} thumbnail`}),
                    el('span', {class: 'channel-title', text: title})
                ])
            );
        });
    }

    function renderChannels(items) {
        channelsList.innerHTML = '';
        if (!Array.isArray(items) || items.length === 0) {
            channelsList.appendChild(
                el('li', {class: 'channel-item'}, [
                    el('img', {class: 'channel-thumb', src: window.session.DEFAULT_THUMB, alt: 'Default channel thumbnail'}),
                    el('span', {class: 'channel-title', text: '{{ _("No channels yet") }}'})
                ])
            );
            return;
        }
        items.forEach(sub => {
            const channelId = sub.channel_id;
            const title = safeText(sub.channel_title || '{{ _("Untitled") }}');
            const thumb = sub.channel_thumbnail_url || window.session.DEFAULT_THUMB;
            channelsList.appendChild(
                el('li', {id: channelId, class: 'channel-item'}, [
                    el('img', {class: 'channel-thumb', src: thumb, alt: `${title} thumbnail`}),
                    el('span', {class: 'channel-title', text: title})
                ])
            );
        });
    }


    function renderFeed(items) {
        feedTbody.innerHTML = '';
        if (!Array.isArray(items)) return;

        items.forEach((item, idx) => {
            const url = item.content_url || item.url || item.link || (`/events/${item.event_id || ''}`);
            const title = safeText(item.title || item.name || `Untitled ${idx + 1}`);
            const rawDesc = safeText(item.body || item.description || '');
            const channel = safeText(item.channel_title || '');
            const desc = rawDesc.length > 100 ? rawDesc.slice(0, 100) : rawDesc;
            const thumb = item.thumbnail_url || '';
            const idval = item.feed_id;
            const dtRaw = safeText(item.date_time || '');
            const viewed = item.viewed != null ? String(item.viewed) : '';

            const tr = el('tr', {
                class: 'feed-item',
                dataset: {id: idval, title: title, desc: desc, date: dtRaw, viewed: viewed, channel: channel},
                style: 'height:48px; border-bottom:1px solid rgba(255,255,255,0.05);'
            }, [
                el('td', {
                    class: 'checkbox-cell',
                    style: 'text-align:center; padding:4px; vertical-align:middle;'
                }, [
                    el('input', {type: 'checkbox', class: 'select-box'})
                ]),
                el('td', {class: 'title-cell', style: 'padding:4px; vertical-align:middle;'}, [
                    el('a', {href: url}, [
                        el('div', {style: 'display:flex; align-items:center; gap:8px; min-width:0;'}, [
                            el('img', {
                                class: 'thumb',
                                src: thumb || DEFAULT_THUMB,
                                alt: '',
                                style: 'width:32px; height:32px; object-fit:cover; border-radius:4px; flex-shrink:0;'
                            }),
                            el('div', {
                                class: 'title',
                                style: 'white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-weight:500;',
                                text: title
                            })
                        ])
                    ])
                ]),
                el('td', {
                    class: 'desc-cell',
                    style: 'padding:4px; vertical-align:middle; font-size:14px; color:rgba(255,255,255,0.8);'
                }, [
                    document.createTextNode(desc)
                ]),
                el('td', {class: 'channel-cell', style: 'padding:4px; vertical-align:middle;'}, [
                    el('a', {href: url}, [
                        el('div', {style: 'display:flex; align-items:center; gap:8px; min-width:0;'}, [
                            el('div', {
                                class: 'channel',
                                style: 'white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-weight:500;',
                                text: channel
                            })
                        ])
                    ])
                ]),
                el('td', {
                    class: 'date-cell',
                    style: 'padding:4px; vertical-align:middle; font-size:14px; white-space:nowrap;'
                }, [
                    document.createTextNode(formatDateLabel(dtRaw))
                ]),
            ]);

            // Stop click on checkbox from bubbling
            tr.querySelector('.select-box').addEventListener('click', (e) => e.stopPropagation());
            feedTbody.appendChild(tr);
        });
    }

    // Expose renderer for reuse by other scripts
    window.renderFeed = renderFeed;

    async function loadFeed(q, page, title_sort, date_sort, channel_sort) {
        const params = [];

        const qv = (q && String(q).trim());
        if (qv) params.push(`q=${encodeURIComponent(qv)}`);

        if (Number.isInteger(page) && page >= 0) {
            params.push(`page=${page}`);
        }

        if (title_sort !== undefined && title_sort !== null) {
            const dir = String(title_sort).toLowerCase() === 'asc' ? 'asc' : 'desc';
            params.push(`ts=${dir}`);
        }

        if (date_sort !== undefined && date_sort !== null) {
            const dir = String(date_sort).toLowerCase() === 'asc' ? 'asc' : 'desc';
            params.push(`ds=${dir}`);
        }

        if (channel_sort !== undefined && channel_sort !== null) {
            const dir = String(channel_sort).toLowerCase() === 'asc' ? 'asc' : 'desc';
            params.push(`cs=${dir}`);
        }

        const req = params.length
            ? `${window.session.userFeedUrl}?${params.join('&')}`
            : window.session.userFeedUrl;

        const feedRes = await fetchWithSession(req);
        const feedJson = await feedRes.json();
        if (feedJson.error) throw new Error(feedJson.message || 'Failed to load feed data');
        renderFeed(feedJson.items || []);
    }

    async function loadMyChannels() {
        const chanRes = await fetchWithSession(window.session.userChannelsUrl)
        const chanJson = await chanRes.json();
        if (chanJson.error) throw new Error(chanJson.message);
        renderMyChannels(chanJson.items || []);
    }

    async function loadSubscribedChannels() {
        const subsRes = await fetchWithSession(window.session.userSubscriptionsUrl)
        const subsJson = await subsRes.json();
        if (subsJson.error) throw new Error(subsJson.message);
        renderChannels(subsJson.items || []);
    }

    async function loadAll() {
        try {
            await Promise.all([
                loadFeed(),
                loadMyChannels(),
                loadSubscribedChannels()
            ]);

        } catch (e) {
            console.error('Failed to initialize user data', e);
        }

        if (typeof initializeFeedTableBehavior === 'function') {
            initializeFeedTableBehavior();
        }
    }

    // Expose a hook name used below to re-run table setup after data loads
    window.initializeFeedTableBehavior = function () {
        // no-op placeholder if later needed; current code binds on static IDs below
    };

    // Initial load without search query
    document.addEventListener('DOMContentLoaded', () => loadAll());

    const btn = document.getElementById('userMenuBtn');
    const menu = document.getElementById('userMenu');
    if (!btn || !menu) return;

    function openMenu() {
        menu.setAttribute('aria-hidden', 'false');
        btn.setAttribute('aria-expanded', 'true');
    }

    function closeMenu() {
        menu.setAttribute('aria-hidden', 'true');
        btn.setAttribute('aria-expanded', 'false');
    }

    function toggleMenu() {
        const isOpen = menu.getAttribute('aria-hidden') === 'false';
        if (isOpen) closeMenu(); else openMenu();
    }

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMenu();
    });

    document.addEventListener('click', (e) => {
        if (!menu.contains(e.target) && e.target !== btn) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMenu();
    });

    // If you host the API at another base URL, set it here or on the element's data attribute.
    const fetchUrlBase = panel ? (panel.dataset.apiBase || '') : '';

    function updateSortArrows() {
        const arrows = document.querySelectorAll('.sort-btn .arrow');
        arrows.forEach(a => {
            const key = a.getAttribute('data-key');
            if (key === sortState.key) {
                // Map dir to arrows: -1 (desc) => ▲, 1 (asc) => ▼
                a.textContent = sortState.dir === -1 ? '▲' : '▼';
            } else {
                a.textContent = '↕';
            }
        });

        // aria-sort for accessibility
        const ths = {
            selected: document.getElementById('th-select'),
            date: document.getElementById('th-date'),
            item: document.getElementById('th-item'),
            channel: document.getElementById('th-channel'),
        };
        Object.entries(ths).forEach(([key, th]) => {
            if (!th) return;
            if (key === sortState.key) {
                th.setAttribute('aria-sort', sortState.dir === 1 ? 'ascending' : 'descending');
            } else {
                th.removeAttribute('aria-sort');
            }
        });
    }

    function toggleSort(key) {
        if (sortState.key === key) {
            // Toggle between ▼ (asc) and ▲ (desc)
            sortState.dir = -sortState.dir;
        } else {
            // Selecting a new column: set others to unselected and start at ▼ (asc)
            sortState.key = key;
            sortState.dir = 1; // start with down arrow for newly selected column
        }
        updateSortArrows();
        Feed();
    }

    function allItems() {
        return Array.from(document.querySelectorAll('#feedTbody .feed-item'));
    }

    function applyFilter() {
        const q = (filterInput.value || '').toLowerCase().trim();
        const items = allItems();

        items.forEach(el => {
            const title = (el.dataset.title || '').toLowerCase();
            const desc = (el.dataset.desc || '').toLowerCase();
            const match = !q || title.includes(q) || desc.includes(q);
            el.dataset.match = match ? '1' : '0';
        });

        currentPage = 0;
        renderPage();
    }

    function visibleMatches() {
        return allItems().filter(el => el.dataset.match !== '0');
    }

    function getSortValue(row, key) {
        if (key === 'selected') {
            const box = row.querySelector('.select-box');
            return box ? (box.checked ? 1 : 0) : 0;
        }
        if (key === 'date') {
            const t = Date.parse(row.dataset.date || '');
            return isNaN(t) ? 0 : t;
        }
        if (key === 'item') {
            return (row.dataset.title || '').toLowerCase();
        }
        if (key === 'channel') {
            return (row.dataset.channel || '').toLowerCase();
        }
        return 0;
    }


    function renderPage() {
        const matches = visibleMatches();
        const total = matches.length;
        const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        currentPage = Math.min(currentPage, pages - 1);

        // Hide all first
        allItems().forEach(el => el.style.display = 'none');

        const start = currentPage * 20;
        const end = start + 20;
        matches.slice(start, end).forEach(el => el.style.display = '');

        if (pageCurrent) {
            pageCurrent.value = pages ? (currentPage + 1) : 0;
            pageCurrent.min = pages ? 1 : 0;
            pageCurrent.max = pages;
        }

        pageInfo.textContent = total
            ? `Showing ${Math.min(end, total)} of ${total} (page ${currentPage + 1} of ${pages})`
            : 'No results';
    }

    function selectAllVisible() {
        const matches = visibleMatches();
        const start = currentPage * PAGE_SIZE;
        const end = start + 20;
        matches.slice(start, end).forEach(el => {
            const box = el.querySelector('.select-box');
            if (box) box.checked = true;
        });
    }

    function selectedIds() {
        return visibleMatches()
            .map(el => ({el, box: el.querySelector('.select-box')}))
            .filter(x => x.box && x.box.checked)
            .map(x => x.el.getAttribute('data-id'))
            .filter(Boolean);
    }

    async function deleteSelected() {
        const ids = selectedIds();
        if (ids.length === 0) {
            alert('No items selected.');
            return;
        }
        if (!confirm(`Delete ${ids.length} selected item(s)? This cannot be undone.`)) return;

        const errors = [];
        for (const id of ids) {
            const candidates = [
                `${fetchUrlBase}/feeds/${encodeURIComponent(id)}`,
                `${fetchUrlBase}/feed/${encodeURIComponent(id)}`
            ];
            let deleted = false;
            for (const url of candidates) {
                try {
                    const resp = await fetch(url, {method: 'DELETE'});
                    if (resp.ok) {
                        deleted = true;
                        break;
                    }
                } catch (_) { /* keep trying */
                }
            }
            if (!deleted) errors.push(id);
        }

        if (errors.length) {
            alert(`Failed to delete ${errors.length} item(s): ${errors.join(', ')}`);
        }

        document.querySelectorAll('#feedTbody .feed-item').forEach(el => {
            const id = el.getAttribute('data-id');
            if (ids.includes(id)) el.remove();
        });

        applyFilter();
    }

    // Event bindings
    applyFilterBtn.addEventListener('click', applyFilter);
    filterInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') applyFilter();
    });

    prevBtn.addEventListener('click', () => {
        if (currentPage > 0) {
            currentPage -= 1;
            renderPage();
        }
    });

    nextBtn.addEventListener('click', () => {
        const total = visibleMatches().length;
        const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        if (currentPage < pages - 1) {
            currentPage += 1;
            renderPage();
        }
    });

    sortTitleBtn.addEventListener('click', () => toggleSort('selected'));
    sortDateBtn.addEventListener('click', () => toggleSort('date'));
    sortItemBtn.addEventListener('click', () => toggleSort('item'));

    headerSelectAll.addEventListener('change', () => {
        const matches = visibleMatches();
        const start = currentPage * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const check = headerSelectAll.checked;
        matches.slice(start, end).forEach(el => {
            const box = el.querySelector('.select-box');
            if (box) box.checked = check;
        });
    });

    if (document.getElementById('selectAllBtn')) {
        document.getElementById('selectAllBtn').addEventListener('click', selectAllVisible);
    }
    deleteBtn.addEventListener('click', deleteSelected);

    // Initialize default view state for filters/pagination when rows get injected
    // Markers will be set after feed rows are rendered
    const observer = new MutationObserver(() => {
        document.querySelectorAll('#feedTbody .feed-item')
            .forEach(el => el.dataset.match = el.dataset.match || '1');
        sortRows();
        renderPage();
    });
    observer.observe(document.getElementById('feedTbody'), {childList: true});

    // Enable server-side search: call API with ?q= and refresh feed
    async function applyServerSearch() {
        const q = (filterInput.value || '').trim();
        if (typeof window.loadAll === 'function') {
            await window.loadAll(q);
        }
    }

    // Wire search to server-backed refresh
    applyFilterBtn.addEventListener('click', applyServerSearch);
    filterInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') applyServerSearch();
    });

    // Sorting handlers
    if (sortTitleBtn) sortTitleBtn.addEventListener('click', () => toggleSort('selected'));
    if (sortDateBtn) sortDateBtn.addEventListener('click', () => toggleSort('date'));
    if (sortItemBtn) sortItemBtn.addEventListener('click', () => toggleSort('item'));
    if (sortChannelBtn) sortChannelBtn.addEventListener('click', () => toggleSort('channel'));
})();
