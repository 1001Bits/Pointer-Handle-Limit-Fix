#pragma once

#include "Configuration.h"
#include "GenerationDiagnostic.h"
#include "HandleTable.h"

namespace sfhcr::monitor
{
    // Blocks on the watcher thread after a successful table commit. The monitor returns only if
    // the manager's free counter no longer looks like the committed table.
    void Run(
        const HandleTableView& table,
        const Settings& settings,
        GenerationDiagnostic& diagnostic,
        const AttributionCallback& attribution = {});
}
