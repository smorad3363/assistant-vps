"""Browser acceptance for the responsive v2 group editor and path tests."""
import os
from pathlib import Path
import time

from playwright.sync_api import expect, sync_playwright


def no_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def protocol_tabs(page, output, local, remote, original):
    """Exercise the same production editor from every method URL."""
    page.set_viewport_size({"width": 1440, "height": 950})
    methods = {
        "wireguard": "ingress-wg-key", "vxlan": "vxlan-vni", "geneve": "geneve-vni",
        "gretap": "gretap-key", "eoip": "eoip-id", "l2tpv2": "ppp-lac",
        "l2tpv3": "ingress-l2tp-tunnel_id", "sit": "ingress-sit-ip", "ipip": "ttl",
    }
    form = page.locator("#v2-group-form")
    for method, field in methods.items():
        link = page.locator(f'[data-page="{method}"]')
        link.click()
        expect(link).to_have_attribute("aria-current", "page")
        expect(page.locator("#v2-group-list")).not_to_contain_text(original["group"]["name"])
        page.locator("#v2-group-new").click()
        expect(form.locator('[data-value="method"]')).to_have_value(method)
        expect(form.locator('[data-value="method"]')).not_to_be_visible()
        expect(form.locator('[name="selection"]')).to_have_value("single")
        expect(form.locator('[data-v2-member] [data-value="node"]')).to_have_value(remote)
        expect(form.locator(f'[data-value="{field}"]')).to_be_visible()
        for other, different in methods.items():
            if other != method:
                expect(form.locator(f'[data-value="{different}"]')).not_to_be_visible()
        if method == "wireguard":
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 950})
                no_overflow(page)
                page.screenshot(path=str(output / f"method-wireguard-{width}.png"), full_page=True)
        if method == "sit":
            expect(form.locator('[data-value="ports"]')).not_to_be_visible()

    saved = []
    submitted = []
    page.route("**/api/v2/groups", lambda route: route.fulfill(json=[original, *saved]))

    def plan(route):
        request = route.request.post_data_json
        submitted.append(request)
        route.fulfill(json={"job": "method-test-preview"})

    def apply(route):
        request = route.request.post_data_json
        assert request["digest"] == "method-plan" and request["id"] == submitted[-1]["id"]
        saved[:] = [{"id": request["group_id"], "owner": local, "revision": 1, "group": request["group"]}]
        route.fulfill(json={"id": "method-test-apply"})

    def job(route):
        if "preview" in route.request.url:
            route.fulfill(json={"status": "done", "result": {"digest": "method-plan", "participants": [local, remote]}})
        else:
            route.fulfill(json={"phase": "committed", "participants": {}, "total": 2, "group_id": saved[0]["id"]})

    page.route("**/api/v2/plan", plan)
    page.route("**/api/v2/apply", apply)
    page.route("**/api/v2/jobs?*", job)
    form.locator('[name="name"]').fill("تونل تهران")
    expect(form.locator('[data-value="ip"]')).to_have_value("")
    form.locator('[data-value="ip"]').fill("192.0.2.11")
    form.locator('[data-value="ports"]').fill("۸۴۴۳")
    form.locator('[data-value="service"]').fill("203.0.113.50")
    form.locator('[data-value="ttl"]').fill("48")
    form.get_by_text("تغییر پورت مقصد و سرعت هر پورت", exact=True).click()
    form.locator('[data-v2-edit="add-port"]').click()
    form.locator('[data-value="override-port"]').fill("8443")
    form.locator('[data-value="override-target"]').fill("443")
    form.locator('[data-value="override-up"]').fill("18")
    form.locator('button[type="submit"]').click()
    expect(form.locator(".topology-preview")).to_be_visible()
    form.locator('#v2-apply-group').click()
    expect(form).not_to_be_visible()
    card = page.locator('#v2-group-list .topology-card').filter(has_text="تونل تهران")
    expect(card).to_contain_text("8443")
    card.get_by_role("button").click()
    expect(form.locator('[data-value="ttl"]')).to_have_value("48")
    expect(form.locator('[data-value="override-target"]')).to_have_value("443")
    form.locator('button[type="submit"]').click()
    expect(form.locator(".topology-preview")).to_be_visible()
    assert len(submitted) == 2
    first, reopened = submitted
    assert first["group"] == reopened["group"] and reopened["expected_revision"] == 1
    listener, = reopened["group"]["listeners"]
    member, = listener["members"]
    assert listener["ports"] == "8443" and listener["port_map"] == {"8443": 443}
    assert listener["port_limits"] == {"8443": {"up": 18, "down": 0}}
    assert listener["node_id"] == local and member["node_id"] == remote and member["method"] == "ipip"
    assert member["ttl"] == 48 and reopened["group"]["selection"] == "single"
    page.locator('[data-page="wireguard"]').click()
    expect(page.locator('#v2-group-list')).not_to_contain_text("تونل تهران")
    expect(page.locator('#v2-apply-group')).to_be_disabled()

    # Multimember configurations keep all destinations and open in the group editor.
    page.locator('[data-page="direct"]').click()
    group_card = page.locator('#v2-group-list .topology-card').filter(has_text=original["group"]["name"])
    group_card.get_by_role("button", name="ویرایش گروه").click()
    expect(page.locator('[data-page="groups"]')).to_have_attribute("aria-current", "page")
    expect(form.locator('[data-v2-member]')).to_have_count(16)
    expect(form.locator('[name="selection"]')).to_have_value("weighted")
    if output:
        page.set_viewport_size({"width": 1440, "height": 950})
        page.screenshot(path=str(output / "group-editor-desktop.png"))


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
    tip = first.locator('details[data-method="vxlan"]').get_by_role("button", name="راهنمای شناسه شبکه")
    tip.focus()
    expect(page.get_by_role("tooltip")).to_contain_text("دو طرف")
    page.keyboard.press("Escape")
    expect(page.get_by_role("tooltip")).to_have_count(0)
    first.locator('[data-value="method"]').select_option("sit")
    expect(first.locator('[data-value="ingress-sit-ip"]')).to_be_visible()
    expect(first.locator('[data-value="mtu"]')).to_have_attribute("min", "1280")
    expect(form.locator('[data-value="ports"]')).not_to_be_visible()
    expect(first.locator('[data-value="weight"]')).not_to_be_visible()
    expect(first.locator('[data-value="state"] option[value="drain"]')).to_have_attribute("disabled", "")
    first.locator('[data-value="method"]').select_option("direct")
    expect(form.locator('[data-value="ports"]')).to_be_visible()
    expect(first.locator('[data-value="vxlan-vni"]')).not_to_be_visible()
    form.locator('button[type="submit"]').click()
    expect(form.get_by_role("alert")).not_to_be_empty()
    form.locator('[data-value="ports"]').fill("8889")
    for index in range(1, 16):
        form.locator('[data-v2-edit="add"]').click()
        members.nth(index).locator('[data-value="service"]').fill(f"203.0.113.{50 + index}")
    expect(members).to_have_count(16)
    page.locator("#refresh").click()
    expect(form.locator('[name="name"]')).to_have_value(name)
    form.locator('button[type="submit"]').click()
    expect(page.locator(".topology-preview")).to_contain_text("تنظیمات آماده ذخیره است")
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
    expect(page.locator("#v2-bench-result")).to_contain_text("۱۵۰ مگابایت")
    expect(page.locator("#v2-bench-result")).to_contain_text("۱۰۰ مگابیت بر ثانیه (برگشت)")

    for width in (360, 375, 390, 768, 1440):
        page.set_viewport_size({"width": width, "height": 844})
        for target in ("groups", "benchmark"):
            page.locator(f'[data-page="{target}"]').click()
            expect(page.locator(f"#{target}-page")).to_be_visible()
            no_overflow(page)
            if target == "groups" and width == 390:
                assert 0 <= cards.first.bounding_box()["y"] < 360
                toggle = page.get_by_role("button", name="نمایش همه روش‌ها")
                toggle.click()
                expect(page.locator("#method-menu-toggle")).to_have_attribute("aria-expanded", "true")
                page.locator('[data-page="sit"]').click()
                expect(page.locator("#method-menu-toggle")).to_have_attribute("aria-expanded", "false")
                expect(page.locator('[data-page="sit"]')).to_be_in_viewport()
                page.locator('[data-page="groups"]').click()
                assert 0 <= cards.first.bounding_box()["y"] < 360
            if width in (390, 1440):
                page.screenshot(path=str(output / f"v2-{target}-{width}.png"))
    for form_id in ("v2-group-form", "v2-bench-form", "settings-form"):
        missing = page.locator(f'#{form_id} input:not([type="hidden"]), #{form_id} select, #{form_id} textarea').evaluate_all(
            'fields => fields.filter(input => !input.closest(".field-with-help")).map(input => input.name || input.dataset.value)')
        assert not missing, (form_id, missing)
    protocol_tabs(page, output, local, remote, original)


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
        try:
            run(page, output)
        except Exception:
            print(f"Browser errors: {failures}")
            if page.locator('#toast').is_visible():
                print(page.locator('#toast').inner_text())
            page.screenshot(path=str(output / "v2-failure.png"))
            raise
        assert not failures, failures
        print("PASS: method pages, protocol settings, port editors, create/apply/reopen, group navigation, benchmarks and five widths.")
