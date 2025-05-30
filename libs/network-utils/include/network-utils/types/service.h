#pragma once
#include <QString>
#include <compare> // For std::strong_ordering
#include <QMetaType> // For Q_DECLARE_METATYPE

struct Service {
    QString name;
    QString toString() const { return name; }

    bool operator==(const Service &other) const noexcept {
        return name == other.name;
    }
    std::strong_ordering operator<=>(const Service &other) const noexcept {
        int cmp = QString::compare(name, other.name);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
};

Q_DECLARE_METATYPE(Service)
