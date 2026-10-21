import time
from playwright.sync_api import sync_playwright

def capture_all():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        # Use high quality desktop viewport
        context = browser.new_context(
            viewport={"width": 1707, "height": 932},
            device_scale_factor=1.0
        )
        page = context.new_page()
        
        # 1. Overview
        print("Navigating to app...")
        page.goto("http://127.0.0.1:8000/?fixture=sql_injection&review=1&v=10")
        page.wait_for_timeout(3000)
        
        # Ensure finding is selected if needed
        card = page.query_selector(".finding-card")
        if card:
            card.click()
            page.wait_for_timeout(500)
            
        page.screenshot(path="assets/workstation_overview.png")
        print("1. workstation_overview.png saved")
        
        # 2. Exploit Advisory Modal
        print("Opening Exploit Advisory Modal...")
        explain_btn = page.query_selector("#explainFindingBtn")
        if explain_btn and explain_btn.is_visible():
            explain_btn.click()
            page.wait_for_timeout(1500)
            page.screenshot(path="assets/exploit_advisory_modal.png")
            print("2. exploit_advisory_modal.png saved")
            
            # Close modal
            close_btn = page.query_selector("#closeExplainBtn")
            if close_btn:
                close_btn.click()
            else:
                page.keyboard.press("Escape")
            page.wait_for_timeout(800)
        else:
            print("Error: #explainFindingBtn not visible")
            
        # 3. Compliance Matrix Drawer
        print("Opening Compliance Matrix Drawer...")
        comp_btn = page.query_selector("#complianceBtn")
        if comp_btn:
            comp_btn.click()
            page.wait_for_timeout(1500)
            page.screenshot(path="assets/compliance_matrix_drawer.png")
            print("3. compliance_matrix_drawer.png saved")
            
            # Close drawer
            close_comp = page.query_selector("#closeComplianceBtn")
            if close_comp:
                close_comp.click()
            else:
                page.keyboard.press("Escape")
            page.wait_for_timeout(800)
        else:
            print("Error: #complianceBtn not found")
            
        # 4. Security Policy Drawer
        print("Opening Security Policy Drawer...")
        pol_btn = page.query_selector("#policyBtn")
        if pol_btn:
            pol_btn.click()
            page.wait_for_timeout(1500)
            page.screenshot(path="assets/security_policy_drawer.png")
            print("4. security_policy_drawer.png saved")
            
            # Close drawer
            close_pol = page.query_selector("#closePolicyBtn")
            if close_pol:
                close_pol.click()
            else:
                page.keyboard.press("Escape")
            page.wait_for_timeout(800)
        else:
            print("Error: #policyBtn not found")
            
        browser.close()
        print("Done capturing all screenshots cleanly!")

if __name__ == "__main__":
    capture_all()
