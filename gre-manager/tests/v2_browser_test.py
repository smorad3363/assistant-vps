"""Browser acceptance for the responsive v2 group editor and path tests."""
import os
from pathlib import Path
import time

from playwright.sync_api import expect, sync_playwright


def no_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def run(page, output):
    page.goto("http://127.0.0.1:8877")
    page.locator("#login-form [name=username]").fill("admin")
    page.locator("#login-form [name=password]").fill("Demo-Panel-2026!")
    page.locator("#login-form button[type=submit]").click()
    page.locator("#app").wait_for(state="visible")
    page.locator('[data-page="groups"]').click()
    page.locator("#v2-group-new").click()
    form = page.locator("#v2-group-form")
    name = "مسیر گروهی با نام بلند برای پوشش رابط موبایل و دسکتاپ"
    form.locator('[name="name"]').fill(name)
    form.locator('[data-v2-listener] [data-value="ip"]').fill("192.0.2.11")
    form.locator('[data-value="ports"]').fill("99999")
    members = form.locator("[data-v2-member]")
    first = members.first
    first.locator('[data-value="service"]').fill("203.0.113.50")
    first.locator('[data-value="method"]').select_option("vxlan")
    expect(first.locator('[data-value="vxlan-vni"]')).to_be_visible()
    expect(first.locator('[data-value="ttl"]')).not_to_be_visible()
    tip = first.get_by_role("button", name="راهنمای شناسهٔ VNI")
    tip.focus()
    expect(page.get_by_role("tooltip")).to_contain_text("۲۴ بیتی")
    page.keyboard.press("Escape")
    expect(page.get_by_role("tooltip")).to_have_count(0)
    first.locator('[data-value="method"]').select_option("direct")
    expect(first.locator('[data-value="vxlan-vni"]')).not_to_be_visible()
    form.locator('button[type="submit"]').click()
    expect(form.get_by_role("alert")).not_to_be_empty()
    form.locator('[data-value="ports"]').fill("8889")
    for index in range(1, 16):
        form.locator('[data-v2-edit="add"]').click()
        members.nth(index).locator('[data-value="service"]').fill(f"203.0.113.{50 + index}")
    expect(members).to_have_count(16)
    page.locator("#v2-groups-refresh").click()
    expect(form.locator('[name="name"]')).to_have_value(name)
    form.locator('button[type="submit"]').click()
    expect(page.locator(".topology-preview")).to_contain_text("پیش‌نمایش تأیید شد")
    page.locator("#v2-apply-group").click()
    cards = page.locator(".topology-card")
    expect(cards.first).to_contain_text(name)
    original = page.evaluate("fetch('/api/v2/groups').then(response => response.json())")[0]
    local = original["owner"]
    remote = "a" * 32
    topology = page.evaluate("fetch('/api/v2/topology').then(response => response.json())")
    topology["paired_nodes"].append({"id": remote, "hostname": "مقصد آزمایشی"})
    other = {**original, "id": "b" * 32, "group": {**original["group"], "name": "لینک قطع‌شده"}}
    member_id = other["group"]["listeners"][0]["members"][0]["id"]
    other["health"] = {member_id: {"checked": time.time(), "link": False}}
    page.route("**/api/v2/groups", lambda route: route.fulfill(json=[original, other]))
    page.route("**/api/v2/topology", lambda route: route.fulfill(json=topology))
    page.locator("#v2-groups-refresh").click()
    expect(cards.first).to_contain_text("لینک قطع‌شده")
    expect(cards.first).to_contain_text("نیاز به بررسی")
    cards.first.locator('summary').click()
    expect(cards.first.locator('details')).to_contain_text("لینک قطع")

    peer_ip = {local: "192.0.2.11", remote: "203.0.113.50"}

    def capabilities(route):
        node = route.request.post_data_json["node_id"]
        route.fulfill(json={"node_id": node, "addresses": [peer_ip[node]], "methods": ["gre", "ipip"], "max_seconds": 300})

    def preview(route):
        details = route.request.post_data_json
        assert details["duration_s"] == 37 and details["methods"] == [{"method": "gre", "duration_s": 37}]
        route.fulfill(json={"digest": "test", "transfer_seconds": 37, "max_seconds": 300, "rate": 1250000, "estimated_bytes": 10_000_000})

    def results(route):
        route.fulfill(json={"phase": "done", "id": "bench-test", "plan": {"request": {"parallel": False},
            "methods": [{"method": "gre", "directions": [18, 19]}]}, "results": {"gre": {
                "received_bytes": 150_000_000, "peak_mbps": 100, "peak_direction": "inbound", "finished": True,
                "directions": {"outbound": {"elapsed_ns": 18_000_000_000, "received_bytes": 50_000_000, "peak_second_bytes": 6_250_000},
                               "inbound": {"elapsed_ns": 19_000_000_000, "received_bytes": 100_000_000, "peak_second_bytes": 12_500_000}}}}})

    page.route("**/api/v2/benchmark.capabilities", capabilities)
    page.route("**/api/v2/benchmark.plan", preview)
    page.route("**/api/v2/benchmark.start", results)
    page.route("**/api/v2/benchmark.status?*", results)
    page.locator('[data-page="benchmark"]').click()
    benchmark = page.locator("#v2-bench-form")
    benchmark.locator('[name="first_node"]').select_option(local)
    benchmark.locator('[name="second_node"]').select_option(remote)
    expect(benchmark.locator('[name="second"]')).to_have_value(peer_ip[remote])
    benchmark.locator('[name="duration_s"]').fill("۳۷")
    benchmark.locator('button[type="submit"]').click()
    expect(page.locator("#v2-bench-estimate")).to_contain_text("۳۷ ثانیه")
    page.locator("#v2-bench-start").click()
    expect(page.locator("#v2-bench-result")).to_contain_text("۱۵۰ MB")
    expect(page.locator("#v2-bench-result")).to_contain_text("۱۰۰ Mbps (برگشت)")

    for width in (360, 375, 390, 768, 1440):
        page.set_viewport_size({"width": width, "height": 844})
        for target in ("groups", "benchmark"):
            page.locator(f'[data-page="{target}"]').click()
            expect(page.locator(f"#{target}-page")).to_be_visible()
            no_overflow(page)
            if target == "groups" and width == 390:
                assert 0 <= cards.first.bounding_box()["y"] < 360
            if width in (390, 1440):
                page.screenshot(path=str(output / f"v2-{target}-{width}.png"))
    for form_id in ("v2-group-form", "v2-bench-form", "settings-form"):
        missing = page.locator(f'#{form_id} input:not([type="hidden"]), #{form_id} select, #{form_id} textarea').evaluate_all(
            'fields => fields.filter(input => !input.closest(".field-with-help")).map(input => input.name || input.dataset.value)')
        assert not missing, (form_id, missing)


if __name__ == "__main__":
    output = Path(os.environ.get("BROWSER_OUTPUT", "test-output"))
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        executable = os.environ.get("CHROMIUM_PATH")
        options = {"executable_path": executable} if executable else {}
        browser = playwright.chromium.launch(headless=True, **options)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        failures = []
        page.on("pageerror", lambda error: failures.append(str(error)))
        run(page, output)
        assert not failures, failures
        print("PASS: v2 creation, apply, 16 members, failed-path priority, field help, benchmark form and five widths.")
