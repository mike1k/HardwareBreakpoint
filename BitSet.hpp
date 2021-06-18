#pragma once

//
// Limited to 64 bits
//
template<unsigned bits>
class BitSet
{
    static_assert(bits <= 64, "Bit amount has exceeded the limit");

    std::uint64_t _v : bits;

public:
    constexpr BitSet() noexcept
        : _v{}
    {
    }

    template<typename T>
    constexpr BitSet(T v) noexcept
        : _v{ static_cast<decltype(_v)>(v) }
    {
    }

    template<typename T>
    constexpr void Set(T v) noexcept
    {
        _v = static_cast<decltype(_v)>(v);
    }

    constexpr void SetBit(std::size_t idx, const bool value) noexcept
    {
        auto pos = static_cast<decltype(_v)>(1 << idx);

        if (value)
            _v |= pos;
        else
            _v &= ~pos;
    }

    constexpr void SetBits(std::size_t idx, const std::uint8_t value) noexcept
    {
        _v |= (value << (idx - 1));
    }

    constexpr void FlipBit(std::size_t idx) noexcept
    {
        auto pos = static_cast<decltype(_v)>(1 << idx);

        _v ^= pos;
    }

    constexpr void Flip() noexcept
    {
        _v = ~_v;
    }

    constexpr bool IsBitSet(std::size_t idx) const noexcept
    {
        return (_v & static_cast<decltype(_v)>(1 << idx)) != 0;
    }


    constexpr auto ExtractBits(std::size_t start_idx, std::size_t end_idx) const noexcept
    {
        auto mask = ((1 << ((1 + end_idx) - start_idx)) - 1) << start_idx;

        return (mask & _v);
    }

    void PrintBits(bool nibbled = false) const
    {
        int idx{ bits };

        do
        {
            if ((_v >> idx--) & 1)
                std::cout << "1";
            else
                std::cout << "0";

            if (nibbled && (idx % 4) == 0)
                std::cout << " ";
        } while (idx >= 0);

        std::cout << std::endl;
    }

    constexpr auto ToValue() const noexcept
    {
        return _v;
    }
};

template<typename T>
using TBitSet = BitSet<sizeof(T)* CHAR_BIT>;

