#pragma once
#include <istream>
#include <streambuf>
#include <string>

class MemoryStream : public std::istream {
public:
    explicit MemoryStream(const std::string& content) : std::istream(nullptr), m_buffer(content) {
        rdbuf(&m_buffer);
    }

private:
    class Buffer : public std::streambuf {
    public:
        explicit Buffer(const std::string& content) {
            char* begin = const_cast<char*>(content.data());
            setg(begin, begin, begin + content.size());
        }

    protected:
        pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                         std::ios_base::openmode mode) override {
            if ((mode & std::ios_base::in) == 0 || (mode & std::ios_base::out) != 0) return pos_type(off_type(-1));
            const off_type size = egptr() - eback();
            off_type base = 0;
            if (direction == std::ios_base::cur) base = gptr() - eback();
            else if (direction == std::ios_base::end) base = size;
            else if (direction != std::ios_base::beg) return pos_type(off_type(-1));
            if (offset < -base || offset > size - base) return pos_type(off_type(-1));
            setg(eback(), eback() + base + offset, egptr());
            return pos_type(base + offset);
        }

        pos_type seekpos(pos_type position, std::ios_base::openmode mode) override {
            return seekoff(static_cast<off_type>(position), std::ios_base::beg, mode);
        }
    };

    Buffer m_buffer;
};
