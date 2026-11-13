"""Browser acceptance on a loopback fixture: no real server credentials."""
import json
import os
from pathlib import Path
import re
import shutil
from playwright.sync_api import sync_playwright

out=Path(os.environ.get("BROWSER_OUTPUT","test-output"));out.mkdir(parents=True,exist_ok=True)
with sync_playwright() as p:
    executable=os.environ.get("CHROMIUM_PATH")
    browser=p.chromium.launch(headless=True,**({"executable_path":executable} if executable else {}))
    page=browser.new_page(viewport={"width":1440,"height":1100},device_scale_factor=1)
    failures=[]
    page.on("pageerror",lambda e:failures.append(str(e)))
    page.goto("http://127.0.0.1:8877")
    page.locator("#login-form [name=username]").fill("admin")
    page.locator("#login-form [name=password]").fill("Demo-Panel-2026!")
    page.locator("#login-form button[type=submit]").click()
    page.locator("#app").wait_for(state="visible")
    assert page.locator(".connection").count()==2
    page.screenshot(path=str(out/"gre-desktop.png"),full_page=True)
    page.locator("#add-connection").click()
    page.locator("#connection-dialog").wait_for(state="visible")
    page.locator("#connection-form [name=name]").fill("Browser test")
    page.locator("#connection-form [name=server_id]").select_option(index=1)
    page.locator("#connection-form [name=target_host]").fill("203.0.113.90")
    page.locator("#connection-form [name=listen_ip]").select_option("192.0.2.11")
    page.locator("#connection-form [name=outer_local]").select_option("192.0.2.11")
    page.locator("#connection-form [value=selected]").check()
    page.locator("#connection-form [name=ports]").fill("9999")
    page.screenshot(path=str(out/"gre-form.png"),full_page=True)
    page.locator("#connection-form button[type=submit]").click()
    page.get_by_text("Browser test",exact=True).first.wait_for(state="visible")
    row=page.locator(".connection").filter(has=page.get_by_text("Browser test",exact=True))
    row.locator('[data-action=edit]').click()
    page.locator("#connection-form [name=name]").fill("Browser edited")
    page.locator("#connection-form button[type=submit]").click()
    page.get_by_text("Browser edited",exact=True).first.wait_for(state="visible")
    row=page.locator(".connection").filter(has=page.get_by_text("Browser edited",exact=True))
    row.locator('[data-action=delete]').click()
    page.locator("#confirm-submit").click()
    page.get_by_text("Browser edited",exact=True).wait_for(state="detached")
    page.locator('[data-page=direct]').click()
    assert page.locator("#page-title").inner_text()=="انتقال مستقیم"
    page.screenshot(path=str(out/"direct-desktop.png"),full_page=True)
    page.locator('[data-page=settings]').click()
    page.screenshot(path=str(out/"settings-desktop.png"),full_page=True)
    page.locator('#settings-form [name=retention_days]').fill('14')
    page.locator('#settings-form button[type=submit]').click()
    page.wait_for_timeout(1800)
    assert page.locator('#settings-form [name=retention_days]').input_value()=='14'
    for width in (375,390,768):
        page.set_viewport_size({"width":width,"height":844})
        for tab in ('gre','direct','settings'):
            page.locator(f'[data-page={tab}]').click()
            assert not page.evaluate('document.documentElement.scrollWidth>window.innerWidth'),(width,tab)
            page.screenshot(path=str(out/f'{tab}-{width}.png'),full_page=True)
        page.locator('[data-page=gre]').click()
        page.locator('#add-connection').click()
        assert not page.evaluate('document.querySelector("#connection-dialog").scrollWidth>window.innerWidth')
        page.locator('#connection-dialog [data-close]').first.click()
    page.emulate_media(reduced_motion='reduce')
    page.locator('#add-connection').click()
    assert page.locator('#connection-dialog').is_visible()
    page.keyboard.press('Escape')
    assert not page.locator('#connection-dialog').is_visible()
    assert not failures,failures
    print(json.dumps({'result':'PASS','console_errors':failures,'viewports':[375,390,768,1440],'flows':['login','create','edit','delete','settings','keyboard escape','reduced motion']}))
    browser.close()
