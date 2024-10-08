<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class AdminController extends AbstractController
{
    #[Route('/admin', name: 'app_admin')]
    public function index(): Response
    {
    // Check if the user has the ROLE_ADMIN
    $this->denyAccessUnlessGranted('ROLE_ADMIN');

    return $this->render('admin/dashboard.html.twig');
    }
}
