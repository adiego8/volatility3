# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Type

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class ImageCopy(plugins.PluginInterface):
    """Copies a physical layer out as a raw DD image"""

    default_block_size = 1024 * 1024 * 5

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer"
            ),
            requirements.StringRequirement(
                name="output-image",
                description="Writes a raw DD image out to `output-image`",
            ),
            requirements.IntRequirement(
                name="block_size",
                description="Size of blocks to copy over",
                default=cls.default_block_size,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="count",
                description="Show status of copy in byte count",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def human_readable(value: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if value < 1024:
                return "{0:.2f} {1}".format(value, unit)
            value /= 1024
        return "{0:.2f} TB".format(value)

    def _generator(self):
        layer_name = "memory_layer"

        if layer_name not in self.context.layers:
            yield 0, (f"Layer Name {layer_name} does not exist",)
        else:
            default_output_name = f"{layer_name}.raw"
            output_name = self.config.get("output-image", default_output_name)

            try:
                layer = self.context.layers[layer_name]

                chunk_size = self.default_block_size
                if self.config.get("block_size"):
                    chunk_size = self.config["block_size"]

                count = self.config.get("count")
                if count:
                    progress = 0

                file_handle = self.open(output_name)

                for i in range(0, layer.maximum_address, chunk_size):
                    current_chunk_size = min(chunk_size, layer.maximum_address + 1 - i)
                    data = layer.read(i, current_chunk_size, pad=True)
                    file_handle.write(data)

                    if count:
                        progress += current_chunk_size
                        self._progress_callback(
                            (i / layer.maximum_address) * 100,
                            self.human_readable(progress),
                        )
                    else:
                        self._progress_callback(
                            (i / layer.maximum_address) * 100, f"Copying image..."
                        )

                file_handle.close()

            except IOError as excp:
                yield 0, (f"Image cannot be copied to {output_name}: {excp}",)

            yield 0, (f"Image has been copied to {output_name}",)

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
