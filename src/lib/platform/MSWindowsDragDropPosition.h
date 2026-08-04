/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#pragma once

#include <cstdint>

namespace inputleap {

std::int32_t calculateDropWindowOrigin(
    std::int32_t cursor,
    std::int32_t virtualOrigin,
    std::int32_t virtualExtent,
    std::int32_t windowSize);

} // namespace inputleap
