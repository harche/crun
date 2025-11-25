/*
 * crun - OCI runtime written in C
 *
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <yyjson.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

static char doc[] = "OCI runtime";

static struct argp_option options[] = { { 0 } };

static char args_doc[] = "features";

static error_t
parse_opt (int key, char *arg arg_unused, struct argp_state *state arg_unused)
{
  if (key != ARGP_KEY_NO_ARGS)
    {
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

static void
add_string_to_json (yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, const char *value)
{
  yyjson_mut_obj_add_str (doc, obj, key, value);
}

static void
add_bool_to_json (yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, int value)
{
  yyjson_mut_obj_add_bool (doc, obj, key, value);
}

static void
add_bool_str_to_json (yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, int value)
{
  const char *val = value ? "true" : "false";
  yyjson_mut_obj_add_str (doc, obj, key, val);
}

static void
add_array_to_json (yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, char **array)
{
  yyjson_mut_val *arr = yyjson_mut_arr (doc);
  size_t i;

  for (i = 0; array[i] != NULL; i++)
    yyjson_mut_arr_add_str (doc, arr, array[i]);

  yyjson_mut_obj_add_val (doc, obj, key, arr);
}

static void
crun_features_add_hooks (yyjson_mut_doc *doc, yyjson_mut_val *root, char **hooks)
{
  add_array_to_json (doc, root, "hooks", hooks);
}

static void
crun_features_add_mount_options (yyjson_mut_doc *doc, yyjson_mut_val *root, char **mount_options)
{
  add_array_to_json (doc, root, "mountOptions", mount_options);
}

static void
crun_features_add_namespaces (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  add_array_to_json (doc, linux_obj, "namespaces", linux->namespaces);
}

static void
crun_features_add_capabilities (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  add_array_to_json (doc, linux_obj, "capabilities", linux->capabilities);
}

static void
crun_features_add_cgroup_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *cgroup = yyjson_mut_obj (doc);

  add_bool_to_json (doc, cgroup, "v1", linux->cgroup.v1);
  add_bool_to_json (doc, cgroup, "v2", linux->cgroup.v2);
  add_bool_to_json (doc, cgroup, "systemd", linux->cgroup.systemd);
  add_bool_to_json (doc, cgroup, "systemdUser", linux->cgroup.systemd_user);

  yyjson_mut_obj_add_val (doc, linux_obj, "cgroup", cgroup);
}

static void
crun_features_add_seccomp_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *seccomp = yyjson_mut_obj (doc);

  add_bool_to_json (doc, seccomp, "enabled", linux->seccomp.enabled);
  if (linux->seccomp.actions)
    add_array_to_json (doc, seccomp, "actions", linux->seccomp.actions);
  if (linux->seccomp.operators)
    add_array_to_json (doc, seccomp, "operators", linux->seccomp.operators);

  yyjson_mut_obj_add_val (doc, linux_obj, "seccomp", seccomp);
}

static void
crun_features_add_mempolicy_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *mempolicy = yyjson_mut_obj (doc);

  if (linux->memory_policy.mode)
    add_array_to_json (doc, mempolicy, "modes", linux->memory_policy.mode);

  if (linux->memory_policy.flags)
    add_array_to_json (doc, mempolicy, "flags", linux->memory_policy.flags);

  yyjson_mut_obj_add_val (doc, linux_obj, "memoryPolicy", mempolicy);
}

static void
crun_features_add_apparmor_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *apparmor = yyjson_mut_obj (doc);

  add_bool_to_json (doc, apparmor, "enabled", linux->apparmor.enabled);

  yyjson_mut_obj_add_val (doc, linux_obj, "apparmor", apparmor);
}

static void
crun_features_add_selinux_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *selinux = yyjson_mut_obj (doc);

  add_bool_to_json (doc, selinux, "enabled", linux->selinux.enabled);

  yyjson_mut_obj_add_val (doc, linux_obj, "selinux", selinux);
}

static void
crun_features_add_mount_ext_info (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *mount_ext = yyjson_mut_obj (doc);
  yyjson_mut_val *idmap = yyjson_mut_obj (doc);

  add_bool_to_json (doc, idmap, "enabled", linux->mount_ext.idmap.enabled);
  yyjson_mut_obj_add_val (doc, mount_ext, "idmap", idmap);

  yyjson_mut_obj_add_val (doc, linux_obj, "mountExtensions", mount_ext);
}

static void
crun_features_add_intel_rdt (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *intel_rdt = yyjson_mut_obj (doc);

  add_bool_to_json (doc, intel_rdt, "enabled", linux->intel_rdt.enabled);

  yyjson_mut_obj_add_val (doc, linux_obj, "intelRdt", intel_rdt);
}

static void
crun_features_add_net_devices (yyjson_mut_doc *doc, yyjson_mut_val *linux_obj, const struct linux_info_s *linux)
{
  yyjson_mut_val *net_devices = yyjson_mut_obj (doc);

  add_bool_to_json (doc, net_devices, "enabled", linux->net_devices.enabled);

  yyjson_mut_obj_add_val (doc, linux_obj, "netDevices", net_devices);
}

static void
crun_features_add_linux_info (yyjson_mut_doc *doc, yyjson_mut_val *root, const struct linux_info_s *linux)
{
  yyjson_mut_val *linux_obj = yyjson_mut_obj (doc);

  crun_features_add_namespaces (doc, linux_obj, linux);
  crun_features_add_capabilities (doc, linux_obj, linux);
  crun_features_add_cgroup_info (doc, linux_obj, linux);
  crun_features_add_seccomp_info (doc, linux_obj, linux);
  crun_features_add_apparmor_info (doc, linux_obj, linux);
  crun_features_add_selinux_info (doc, linux_obj, linux);
  crun_features_add_mount_ext_info (doc, linux_obj, linux);
  crun_features_add_intel_rdt (doc, linux_obj, linux);
  crun_features_add_net_devices (doc, linux_obj, linux);
  crun_features_add_mempolicy_info (doc, linux_obj, linux);

  yyjson_mut_obj_add_val (doc, root, "linux", linux_obj);
}

static void
crun_features_add_annotations_info (yyjson_mut_doc *doc, yyjson_mut_val *root, const struct annotations_info_s *annotation)
{
  yyjson_mut_val *annotations = yyjson_mut_obj (doc);

  if (! is_empty_string (annotation->io_github_seccomp_libseccomp_version))
    add_string_to_json (doc, annotations, "io.github.seccomp.libseccomp.version", annotation->io_github_seccomp_libseccomp_version);

  add_bool_str_to_json (doc, annotations, "org.opencontainers.runc.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);
  add_bool_str_to_json (doc, annotations, "run.oci.crun.checkpoint.enabled", annotation->run_oci_crun_checkpoint_enabled);

  add_string_to_json (doc, annotations, "run.oci.crun.commit", annotation->run_oci_crun_commit);
  add_string_to_json (doc, annotations, "run.oci.crun.version", annotation->run_oci_crun_version);

  add_bool_str_to_json (doc, annotations, "run.oci.crun.wasm", annotation->run_oci_crun_wasm);

  yyjson_mut_obj_add_val (doc, root, "annotations", annotations);
}

static void
crun_features_add_potentially_unsafe_config_annotations_info (yyjson_mut_doc *doc, yyjson_mut_val *root, char **annotations)
{
  add_array_to_json (doc, root, "potentiallyUnsafeConfigAnnotations", annotations);
}

int
crun_command_features (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  cleanup_struct_features struct features_info_s *info = NULL;
  int first_arg = 0, ret = 0;
  libcrun_context_t crun_context = {
    0,
  };
  yyjson_mut_doc *doc = NULL;
  yyjson_mut_val *root = NULL;
  char *json_output = NULL;

  argp_parse (&run_argp, argc, argv, 0, 0, &options);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Call the function in features.c to gather the feature information
  ret = libcrun_container_get_features (&crun_context, &info, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Prepare the JSON output
  doc = yyjson_mut_doc_new (NULL);
  if (doc == NULL)
    return libcrun_make_error (err, 0, "Failed to initialize json structure");

  root = yyjson_mut_obj (doc);
  if (root == NULL)
    {
      yyjson_mut_doc_free (doc);
      return libcrun_make_error (err, 0, "Failed to create json root object");
    }
  yyjson_mut_doc_set_root (doc, root);

  // Add ociVersionMin field
  add_string_to_json (doc, root, "ociVersionMin", info->oci_version_min);

  // Add ociVersionMax field
  add_string_to_json (doc, root, "ociVersionMax", info->oci_version_max);

  // Add hooks array
  crun_features_add_hooks (doc, root, info->hooks);

  // Add mountOptions array
  crun_features_add_mount_options (doc, root, info->mount_options);

  // Add linux struct info
  crun_features_add_linux_info (doc, root, &info->linux);

  // Add annotations struct info
  crun_features_add_annotations_info (doc, root, &info->annotations);

  // Add potentially unsafe config annotations info
  crun_features_add_potentially_unsafe_config_annotations_info (doc, root, info->potentially_unsafe_annotations);

  json_output = yyjson_mut_write (doc, YYJSON_WRITE_PRETTY, NULL);

  if (json_output)
    {
      printf ("%s", json_output);
      free (json_output);
    }

  yyjson_mut_doc_free (doc);

  return 0;
}
