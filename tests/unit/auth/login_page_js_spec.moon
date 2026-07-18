-- tests/unit/auth/login_page_js_spec.moon
-- Le JS des pages de formulaire (login/register/password) doit borner tous ses
-- fetch par un timeout (AbortController) : sans cela, une connexion TCP jamais
-- établie (pool navigateur gelé après une mise en veille) laisse le bouton
-- « Connexion… » bloqué indéfiniment (bug HAR 2026-07-17).

pages = require "auth.pages"

describe "auth.pages JS des formulaires (fetch borné)", ->

  it "CRYPTO_JS définit le helper fetchT avec AbortController", ->
    assert.truthy pages.CRYPTO_JS\find("function fetchT", 1, true)
    assert.truthy pages.CRYPTO_JS\find("AbortController", 1, true)
    assert.truthy pages.CRYPTO_JS\find("abort", 1, true)

  for name in *{ "LOGIN_JS", "REGISTER_JS", "PASSWORD_JS" }
    it "#{name} n'utilise que fetchT, jamais fetch nu", ->
      js = pages[name]
      assert.truthy js, "#{name} doit être exporté par auth.pages"
      assert.truthy js\find("fetchT(", 1, true)
      -- aucun appel direct `fetch(` (précédé d'autre chose que 'T')
      assert.falsy js\match "[^T]fetch%("

  it "LOGIN_JS réactive le bouton en cas d'échec (catch)", ->
    assert.truthy pages.LOGIN_JS\find(".catch", 1, true)
    assert.truthy pages.LOGIN_JS\find("btn.disabled=false", 1, true)

  it "LOGIN_JS rejoue automatiquement la séquence challenge+login", ->
    assert.truthy pages.LOGIN_JS\find("attemptLogin", 1, true)
    assert.truthy pages.LOGIN_JS\find("LOGIN_RETRIES", 1, true)
    assert.truthy pages.LOGIN_JS\find("remaining-1", 1, true)
