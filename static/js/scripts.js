document.addEventListener('DOMContentLoaded', function() {
    // Notificaciones para técnicos
    if (document.querySelector('#liveToast')) {
        const toastLive = document.getElementById('liveToast');
        const toast = new bootstrap.Toast(toastLive);
        
        const socket = io();
        
        socket.on('nueva_solicitud', function(data) {
            document.getElementById('toast-solicitante').textContent = data.solicitante;
            document.getElementById('toast-trabajo').textContent = data.tipo_trabajo;
            toast.show();
        });
    }
});