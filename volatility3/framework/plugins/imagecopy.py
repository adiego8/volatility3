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
                default = False,
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

    @classmethod
    def write_layer(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        preferred_name: str,
        open_method: Type[plugins.FileHandlerInterface],
        progress_callback: constants.ProgressCallback,
        count: bool,
        chunk_size: int,
    ) -> Optional[plugins.FileHandlerInterface]:
        """Copies the specified layer to a FileHandler, using the provided context. Returns the FileHandler on success or None on failure.

        Args:
            context (interfaces.context.ContextInterface): The context from which to read the specified layer.
            layer_name (str): The name of the layer to write out.
            preferred_name (str): The preferred filename for the output file.
            open_method (Type[plugins.FileHandlerInterface]): Class for creating FileHandler context managers.
            progress_callback (constants.ProgressCallback): Function that takes a percentage and a string to display progress.
            chunk_size (int): Size for the chunks that should be written (defaults to 0x500000).
            count (bool): Whether to track progress for the progress callback output.

        Returns:
            Optional[plugins.FileHandlerInterface]: The FileHandler used for writing the layer, or None on failure.
        """
        if layer_name not in context.layers:
            raise exceptions.LayerException("Layer not found")

        layer = context.layers[layer_name]

        if chunk_size is None:
            chunk_size = cls.default_block_size

        file_handle = open_method(preferred_name)

        if count:
            progress = 0

        for i in range(0, layer.maximum_address, chunk_size):
            current_chunk_size = min(chunk_size, layer.maximum_address + 1 - i)
            data = layer.read(i, current_chunk_size, pad=True)
            file_handle.write(data)

            if count:
                progress += current_chunk_size
                progress_callback((i / layer.maximum_address) * 100, cls.human_readable(progress))
            else:
                progress_callback(
                    (i / layer.maximum_address) * 100, f"Copying image..."
                )

        return file_handle

    def _generator(self):
        # to create a raw copy of an image we need to access the memory layer
        layer_name = "memory_layer"

        if layer_name not in self.context.layers:
            yield 0, (f"Layer Name {layer_name} does not exist",)
        else:
            default_output_name = f"{layer_name}.raw"
            output_name = self.config.get("output-image", default_output_name)

            try:
                file_handle = self.write_layer(
                    self.context,
                    layer_name,
                    output_name,
                    self.open,
                    self._progress_callback,
                    self.config.get("count"),
                    self.config.get("block_size", self.default_block_size),
                )
                file_handle.close()

            except IOError as excp:
                yield 0, (
                    f"Image cannot be copied to {output_name}: {excp}",
                )

            yield 0, (f"Image has been copied to {output_name}",)

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
