#pragma once
#include <cstddef>
#include <string>
#include <vector>
namespace fivem::lua {
enum class Tok {
    End,
    Space,
    LineComment,
    BlockComment,
    String,
    Number,
    Name,
    Symbol,
};
struct Token {
    Tok kind = Tok::End;
    size_t begin = 0;
    size_t end = 0;
    std::string text;
    bool multiline = false;
    bool closed = true;
};
std::vector<Token> tokenize(const std::string& source);
bool isIdentifierStart(char c);
bool isIdentifierChar(char c);
bool isKeyword(const std::string& name);
bool isOpeningKeyword(const std::string& name);
bool isClosingKeyword(const std::string& name);
} 