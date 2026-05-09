local with_dev
with_dev = require("spec.helpers").with_dev
return describe("moon", function()
  local moon
  with_dev(function()
    moon = require("moon")
  end)
  describe("type", function()
    it("returns 'class' for a class", function()
      local Test
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Test"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Test = _class_0
      end
      return assert.equal("class", moon.type(Test))
    end)
    it("returns the class for an instance", function()
      local Test
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Test"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Test = _class_0
      end
      return assert.equal(Test, moon.type(Test()))
    end)
    it("returns 'table' for __base", function()
      local Test
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Test"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Test = _class_0
      end
      return assert.equal("table", moon.type(Test.__base))
    end)
    it("returns 'table' for __base with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.equal("table", moon.type(Child.__base))
      return assert.equal("table", moon.type(Parent.__base))
    end)
    it("returns primitive type for non-tables", function()
      assert.equal("number", moon.type(1))
      assert.equal("boolean", moon.type(true))
      assert.equal("nil", moon.type(nil))
      assert.equal("string", moon.type("hello"))
      return assert.equal("function", moon.type(function() end))
    end)
    it("returns 'table' for plain tables", function()
      assert.equal("table", moon.type({ }))
      return assert.equal("table", moon.type({
        hello = "world"
      }))
    end)
    it("returns 'class' for classes with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.equal("class", moon.type(Parent))
      return assert.equal("class", moon.type(Child))
    end)
    return it("works with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.equal(Child, moon.type(Child()))
      assert.equal(Parent, moon.type(Parent()))
      assert.equal("table", moon.type(Child.__base))
      return assert.equal("table", moon.type(Parent.__base))
    end)
  end)
  it("should get upvalue", function()
    local fn
    do
      local hello = "world"
      fn = function()
        return hello
      end
    end
    return assert.same(moon.debug.upvalue(fn, "hello"), "world")
  end)
  it("should set upvalue", function()
    local fn
    do
      local hello = "world"
      fn = function()
        return hello
      end
    end
    moon.debug.upvalue(fn, "hello", "foobar")
    return assert.same(fn(), "foobar")
  end)
  it("should run with scope", function()
    local scope = {
      hello = function() end
    }
    spy.on(scope, "hello")
    moon.run_with_scope((function()
      return hello()
    end), scope)
    return assert.spy(scope.hello).was.called()
  end)
  it("should have access to old environment", function()
    local scope = { }
    local res = moon.run_with_scope((function()
      return math
    end), scope)
    return assert.same(res, math)
  end)
  it("should created bound proxy", function()
    local Hello
    do
      local _class_0
      local _base_0 = {
        state = 10,
        method = function(self, val)
          return "the state: " .. tostring(self.state) .. ", the val: " .. tostring(val)
        end
      }
      _base_0.__index = _base_0
      _class_0 = setmetatable({
        __init = function() end,
        __base = _base_0,
        __name = "Hello"
      }, {
        __index = _base_0,
        __call = function(cls, ...)
          local _self_0 = setmetatable({}, _base_0)
          cls.__init(_self_0, ...)
          return _self_0
        end
      })
      _base_0.__class = _class_0
      Hello = _class_0
    end
    local hello = Hello()
    local bound = moon.bind_methods(hello)
    return assert.same(bound.method("xxx"), "the state: 10, the val: xxx")
  end)
  it("should create defaulted table", function()
    local fib = moon.defaultbl({
      [0] = 0,
      [1] = 1
    }, function(self, i)
      return self[i - 1] + self[i - 2]
    end)
    local _ = fib[7]
    return assert.same(fib, {
      [0] = 0,
      1,
      1,
      2,
      3,
      5,
      8,
      13
    })
  end)
  it("should extend", function()
    local t1 = {
      hello = "world's",
      cool = "shortest"
    }
    local t2 = {
      cool = "boots",
      cowboy = "hat"
    }
    local out = moon.extend(t1, t2)
    return assert.same({
      out.hello,
      out.cool,
      out.cowboy
    }, {
      "world's",
      "shortest",
      "hat"
    })
  end)
  it("should make a copy", function()
    local x = {
      "hello",
      yeah = "man"
    }
    local y = moon.copy(x)
    x[1] = "yikes"
    x.yeah = "woman"
    return assert.same(y, {
      "hello",
      yeah = "man"
    })
  end)
  it("should mixin", function()
    local TestModule
    do
      local _class_0
      local _base_0 = {
        show_var = function(self)
          return "var is: " .. tostring(self.var)
        end
      }
      _base_0.__index = _base_0
      _class_0 = setmetatable({
        __init = function(self, var)
          self.var = var
        end,
        __base = _base_0,
        __name = "TestModule"
      }, {
        __index = _base_0,
        __call = function(cls, ...)
          local _self_0 = setmetatable({}, _base_0)
          cls.__init(_self_0, ...)
          return _self_0
        end
      })
      _base_0.__class = _class_0
      TestModule = _class_0
    end
    local Second
    do
      local _class_0
      local _base_0 = { }
      _base_0.__index = _base_0
      _class_0 = setmetatable({
        __init = function(self)
          return moon.mixin(self, TestModule, "hi")
        end,
        __base = _base_0,
        __name = "Second"
      }, {
        __index = _base_0,
        __call = function(cls, ...)
          local _self_0 = setmetatable({}, _base_0)
          cls.__init(_self_0, ...)
          return _self_0
        end
      })
      _base_0.__class = _class_0
      Second = _class_0
    end
    local obj = Second()
    return assert.same(obj:show_var(), "var is: hi")
  end)
  it("should mixin object", function()
    local First
    do
      local _class_0
      local _base_0 = {
        val = 10,
        get_val = function(self)
          return "the val: " .. tostring(self.val)
        end
      }
      _base_0.__index = _base_0
      _class_0 = setmetatable({
        __init = function() end,
        __base = _base_0,
        __name = "First"
      }, {
        __index = _base_0,
        __call = function(cls, ...)
          local _self_0 = setmetatable({}, _base_0)
          cls.__init(_self_0, ...)
          return _self_0
        end
      })
      _base_0.__class = _class_0
      First = _class_0
    end
    local Second
    do
      local _class_0
      local _base_0 = {
        val = 20
      }
      _base_0.__index = _base_0
      _class_0 = setmetatable({
        __init = function(self)
          return moon.mixin_object(self, First(), {
            "get_val"
          })
        end,
        __base = _base_0,
        __name = "Second"
      }, {
        __index = _base_0,
        __call = function(cls, ...)
          local _self_0 = setmetatable({}, _base_0)
          cls.__init(_self_0, ...)
          return _self_0
        end
      })
      _base_0.__class = _class_0
      Second = _class_0
    end
    local obj = Second()
    return assert.same(obj:get_val(), "the val: 10")
  end)
  it("should mixin table", function()
    local a = {
      hello = "world",
      cat = "dog"
    }
    local b = {
      cat = "mouse",
      foo = "bar"
    }
    moon.mixin_table(a, b)
    return assert.same(a, {
      hello = "world",
      cat = "mouse",
      foo = "bar"
    })
  end)
  describe("is_class", function()
    it("returns true for a class", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.truthy(moon.is_class(Hello))
    end)
    it("returns false for an instance", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.falsy(moon.is_class(Hello()))
    end)
    it("returns false for __base", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.falsy(moon.is_class(Hello.__base))
    end)
    it("returns false for __base with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.falsy(moon.is_class(Child.__base))
      return assert.falsy(moon.is_class(Parent.__base))
    end)
    it("returns false for plain tables and non-tables", function()
      assert.falsy(moon.is_class({ }))
      assert.falsy(moon.is_class(123))
      assert.falsy(moon.is_class("hello"))
      assert.falsy(moon.is_class(nil))
      return assert.falsy(moon.is_class(true))
    end)
    return it("works with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.truthy(moon.is_class(Parent))
      assert.truthy(moon.is_class(Child))
      return assert.falsy(moon.is_class(Child()))
    end)
  end)
  describe("is_instance and is_class with imposter tables", function()
    it("rejects table with only __base set", function()
      local fake = {
        __base = { }
      }
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
    it("rejects table with __base and non-callable metatable", function()
      local fake = setmetatable({
        __base = { }
      }, {
        __index = { }
      })
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
    it("rejects table with self-referencing __index but no metatable", function()
      local fake = { }
      fake.__index = fake
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
    it("rejects table with __class set directly", function()
      local fake = {
        __class = { }
      }
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
    it("rejects table whose metatable has __class but not self-referencing __index", function()
      local mt = {
        __class = { }
      }
      local fake = setmetatable({ }, mt)
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
    return it("rejects table with self-referencing __index used as its own metatable", function()
      local fake = { }
      fake.__index = fake
      setmetatable(fake, fake)
      assert.falsy(moon.is_class(fake))
      return assert.falsy(moon.is_instance(fake))
    end)
  end)
  describe("is_instance", function()
    it("returns true for an instance", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.truthy(moon.is_instance(Hello()))
    end)
    it("returns false for a class", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.falsy(moon.is_instance(Hello))
    end)
    it("returns false for __base", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.falsy(moon.is_instance(Hello.__base))
    end)
    it("returns false for __base with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.falsy(moon.is_instance(Child.__base))
      return assert.falsy(moon.is_instance(Parent.__base))
    end)
    it("returns false for plain tables and non-tables", function()
      assert.falsy(moon.is_instance({ }))
      assert.falsy(moon.is_instance(123))
      assert.falsy(moon.is_instance("hello"))
      assert.falsy(moon.is_instance(nil))
      return assert.falsy(moon.is_instance(true))
    end)
    return it("works with inheritance", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.truthy(moon.is_instance(Parent()))
      assert.truthy(moon.is_instance(Child()))
      assert.falsy(moon.is_instance(Parent))
      return assert.falsy(moon.is_instance(Child))
    end)
  end)
  describe("is_instance_of", function()
    it("returns true for direct instance", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      return assert.truthy(moon.is_instance_of(Hello(), Hello))
    end)
    it("returns true for instance of parent class", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.truthy(moon.is_instance_of(Child(), Parent))
      return assert.truthy(moon.is_instance_of(Child(), Child))
    end)
    it("returns false for instance of unrelated class", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      local B
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "B"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        B = _class_0
      end
      assert.falsy(moon.is_instance_of(A(), B))
      return assert.falsy(moon.is_instance_of(B(), A))
    end)
    it("returns false for parent instance checked against child class", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      return assert.falsy(moon.is_instance_of(Parent(), Child))
    end)
    it("errors when value is not an instance", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      assert.has_error((function()
        return moon.is_instance_of(Hello, Hello)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of(Hello.__base, Hello)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of({ }, Hello)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of(nil, Hello)
      end), "is_instance_of: expected instance, got nil")
      return assert.has_error((function()
        return moon.is_instance_of(123, Hello)
      end), "is_instance_of: expected instance, got number")
    end)
    it("errors when __base is passed as the value", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.has_error((function()
        return moon.is_instance_of(Parent.__base, Parent)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of(Child.__base, Child)
      end), "is_instance_of: expected instance, got table")
      return assert.has_error((function()
        return moon.is_instance_of(Child.__base, Parent)
      end), "is_instance_of: expected instance, got table")
    end)
    it("returns false when __base is passed as the class", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.falsy(moon.is_instance_of(Parent(), Parent.__base))
      assert.falsy(moon.is_instance_of(Child(), Child.__base))
      return assert.falsy(moon.is_instance_of(Child(), Parent.__base))
    end)
    it("errors when __base is on both sides", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.has_error((function()
        return moon.is_instance_of(Parent.__base, Parent.__base)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of(Child.__base, Child.__base)
      end), "is_instance_of: expected instance, got table")
      assert.has_error((function()
        return moon.is_instance_of(Child.__base, Parent.__base)
      end), "is_instance_of: expected instance, got table")
      return assert.has_error((function()
        return moon.is_instance_of(Parent.__base, Child.__base)
      end), "is_instance_of: expected instance, got table")
    end)
    return it("works with deep inheritance chain", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      local B
      do
        local _class_0
        local _parent_0 = A
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "B",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        B = _class_0
      end
      local C
      do
        local _class_0
        local _parent_0 = B
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "C",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        C = _class_0
      end
      assert.truthy(moon.is_instance_of(C(), A))
      assert.truthy(moon.is_instance_of(C(), B))
      assert.truthy(moon.is_instance_of(C(), C))
      assert.falsy(moon.is_instance_of(A(), B))
      return assert.falsy(moon.is_instance_of(A(), C))
    end)
  end)
  describe("is_subclass_of", function()
    it("returns true for direct child", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      return assert.truthy(moon.is_subclass_of(Child, Parent))
    end)
    it("returns true for deep inheritance", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      local B
      do
        local _class_0
        local _parent_0 = A
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "B",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        B = _class_0
      end
      local C
      do
        local _class_0
        local _parent_0 = B
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "C",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        C = _class_0
      end
      assert.truthy(moon.is_subclass_of(C, A))
      assert.truthy(moon.is_subclass_of(C, B))
      return assert.truthy(moon.is_subclass_of(B, A))
    end)
    it("returns false for same class", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      return assert.falsy(moon.is_subclass_of(A, A))
    end)
    it("returns false for parent checked against child", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      return assert.falsy(moon.is_subclass_of(Parent, Child))
    end)
    it("returns false for unrelated classes", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      local B
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "B"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        B = _class_0
      end
      assert.falsy(moon.is_subclass_of(A, B))
      return assert.falsy(moon.is_subclass_of(B, A))
    end)
    it("returns false for class without parent", function()
      local A
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "A"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        A = _class_0
      end
      local B
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "B"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        B = _class_0
      end
      return assert.falsy(moon.is_subclass_of(A, B))
    end)
    it("returns false when __base is passed as the parent", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.falsy(moon.is_subclass_of(Child, Parent.__base))
      return assert.falsy(moon.is_subclass_of(Child, Child.__base))
    end)
    it("errors when first argument is not a class", function()
      local Hello
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Hello"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Hello = _class_0
      end
      assert.has_error((function()
        return moon.is_subclass_of(Hello(), Hello)
      end), "is_subclass_of: expected class, got table")
      assert.has_error((function()
        return moon.is_subclass_of(Hello.__base, Hello)
      end), "is_subclass_of: expected class, got table")
      assert.has_error((function()
        return moon.is_subclass_of({ }, Hello)
      end), "is_subclass_of: expected class, got table")
      assert.has_error((function()
        return moon.is_subclass_of(nil, Hello)
      end), "is_subclass_of: expected class, got nil")
      return assert.has_error((function()
        return moon.is_subclass_of(123, Hello)
      end), "is_subclass_of: expected class, got number")
    end)
    return it("errors when __base is passed as the first argument", function()
      local Parent
      do
        local _class_0
        local _base_0 = { }
        _base_0.__index = _base_0
        _class_0 = setmetatable({
          __init = function() end,
          __base = _base_0,
          __name = "Parent"
        }, {
          __index = _base_0,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        Parent = _class_0
      end
      local Child
      do
        local _class_0
        local _parent_0 = Parent
        local _base_0 = { }
        _base_0.__index = _base_0
        setmetatable(_base_0, _parent_0.__base)
        _class_0 = setmetatable({
          __init = function(self, ...)
            return _class_0.__parent.__init(self, ...)
          end,
          __base = _base_0,
          __name = "Child",
          __parent = _parent_0
        }, {
          __index = function(cls, name)
            local val = rawget(_base_0, name)
            if val == nil then
              local parent = rawget(cls, "__parent")
              if parent then
                return parent[name]
              end
            else
              return val
            end
          end,
          __call = function(cls, ...)
            local _self_0 = setmetatable({}, _base_0)
            cls.__init(_self_0, ...)
            return _self_0
          end
        })
        _base_0.__class = _class_0
        if _parent_0.__inherited then
          _parent_0.__inherited(_parent_0, _class_0)
        end
        Child = _class_0
      end
      assert.has_error((function()
        return moon.is_subclass_of(Parent.__base, Parent)
      end), "is_subclass_of: expected class, got table")
      return assert.has_error((function()
        return moon.is_subclass_of(Child.__base, Child)
      end), "is_subclass_of: expected class, got table")
    end)
  end)
  return it("should fold", function()
    local numbers = {
      4,
      3,
      5,
      6,
      7,
      2,
      3
    }
    local sum = moon.fold(numbers, function(a, b)
      return a + b
    end)
    return assert.same(sum, 30)
  end)
end)
