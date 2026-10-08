#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
namespace fivem {
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    Json() = default;
    static Json parse(const std::string& text);
    bool isObject() const { return type_ == Type::Object; }
    bool isArray() const { return type_ == Type::Array; }
    bool isString() const { return type_ == Type::String; }
    bool isNumber() const { return type_ == Type::Number; }
    const std::string& asString() const { return str_; }
    double asNumber() const { return num_; }
    const std::vector<std::pair<std::string, Json>>& items() const { return obj_; }
    const std::vector<Json>& arr() const { return array_; }
    bool has(const std::string& key) const;
    const Json& at(const std::string& key) const;
    std::string strAt(const std::string& key, const std::string& def = "") const;
    size_t size() const {
        if (type_ == Type::Array) return array_.size();
        if (type_ == Type::Object) return obj_.size();
        return 0;
    }
private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    std::string str_;
    std::vector<Json> array_;
    std::vector<std::pair<std::string, Json>> obj_;
    static Json parseValue(const std::string& t, size_t& p);
    static Json parseString(const std::string& t, size_t& p);
    static Json parseNumber(const std::string& t, size_t& p);
    static Json parseArray(const std::string& t, size_t& p);
    static Json parseObject(const std::string& t, size_t& p);
    static void skipWs(const std::string& t, size_t& p);
    static std::string decodeString(const std::string& raw);
};
}
