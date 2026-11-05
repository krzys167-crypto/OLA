from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_landing_page_does_not_advertise_an_unverified_stripe_link():
    html = (ROOT / "revenue" / "index.html").read_text(encoding="utf-8")
    assert "buy.stripe.com" not in html
    assert "CI-VERIFIED" in html
    assert "CHECKOUT NOT AVAILABLE" in html
    assert 'aria-disabled="true"' in html
    assert "public customer onboarding flow" in html.lower()


def test_checkout_cta_is_not_a_clickable_anchor():
    html = (ROOT / "revenue" / "index.html").read_text(encoding="utf-8")
    offer = html.split('<div class="offer">', 1)[1].split("</div>", 1)[0]
    assert "<a " not in offer
    assert '<span class="cta cta-disabled"' in offer
