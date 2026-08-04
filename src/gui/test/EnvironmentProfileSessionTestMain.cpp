#include "QInputLeapApplication.h"

#include <gtest/gtest.h>

int main(int argc, char** argv)
{
    QInputLeapApplication application(argc, argv);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS() == 1 ? 1 : 0;
}
