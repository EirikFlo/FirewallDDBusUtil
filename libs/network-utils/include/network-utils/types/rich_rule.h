#pragma once
#include <QString>
#include <compare> // For std::strong_ordering
#include <QMetaType> // For Q_DECLARE_METATYPE

struct RichRule {
    QString rule;
    QString toString() const { return rule; }

    bool operator==(const RichRule &other) const noexcept {
        return rule == other.rule;
    }
    std::strong_ordering operator<=>(const RichRule &other) const noexcept {
        int cmp = QString::compare(rule, other.rule);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
};

Q_DECLARE_METATYPE(RichRule)
