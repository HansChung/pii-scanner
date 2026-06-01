from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from zipfile import BadZipFile, ZipFile


@dataclass(frozen=True)
class EmbeddedImage:
    path: Path
    location: str


MEDIA_PREFIXES = {
    ".docx": "word/media/",
    ".pptx": "ppt/media/",
    ".xlsx": "xl/media/",
}
SUPPORTED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}


def extract_embedded_images(
    source_path: Path,
    extension: str,
    *,
    max_images: int,
    max_image_bytes: int,
) -> list[EmbeddedImage]:
    prefix = MEDIA_PREFIXES.get(extension.lower())
    if not prefix:
        return []
    output_dir = source_path.parent / f".office-images-{uuid.uuid4().hex}"
    images: list[EmbeddedImage] = []
    try:
        with ZipFile(source_path) as archive:
            members = [
                item
                for item in archive.infolist()
                if item.filename.startswith(prefix)
                and Path(item.filename).suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS
                and item.file_size <= max_image_bytes
            ][:max_images]
            if not members:
                return []
            output_dir.mkdir(parents=True, exist_ok=True)
            for index, member in enumerate(members, start=1):
                suffix = Path(member.filename).suffix.lower()
                destination = output_dir / f"image-{index}{suffix}"
                destination.write_bytes(archive.read(member))
                images.append(
                    EmbeddedImage(
                        path=destination,
                        location=f"內嵌圖片 {index} ({Path(member.filename).name})",
                    )
                )
    except BadZipFile:
        return []
    return images


def cleanup_embedded_images(images: list[EmbeddedImage]) -> None:
    parents = {image.path.parent for image in images}
    for parent in parents:
        for path in parent.glob("*"):
            path.unlink(missing_ok=True)
        parent.rmdir()
