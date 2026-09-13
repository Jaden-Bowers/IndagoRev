#pragma once
#include "harness_scope.hpp"
namespace indago {
wb::J normalize_execution_grant(const ProjectStore &, const wb::J &,
                                const wb::J &);
wb::J normalize_experiment(const ProjectStore &, const wb::J &, const wb::J &,
                           wb::J);
wb::J execute_experiment(ProjectStore &, const wb::J &);
wb::J reconcile_experiment(ProjectStore &, const wb::J &, const wb::J &);
wb::J normalize_experiment_cleanup(const ProjectStore &, const wb::J &,
                                   const wb::J &, wb::J);
wb::J cleanup_experiment(ProjectStore &, const wb::J &);
} // namespace indago
